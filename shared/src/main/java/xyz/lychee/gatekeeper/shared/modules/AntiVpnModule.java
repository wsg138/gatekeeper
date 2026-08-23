package xyz.lychee.gatekeeper.shared.modules;

import dev.dejvokep.boostedyaml.block.implementation.Section;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.manager.TaskManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractConditionSet;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.objects.JsonConditionSet;
import xyz.lychee.gatekeeper.shared.objects.TextConditionSet;
import xyz.lychee.gatekeeper.shared.security.AnonymizerConsensus;
import xyz.lychee.gatekeeper.shared.security.AnonymizerType;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.stream.Collectors;

public class AntiVpnModule extends AbstractModule {
    private final Map<Integer, CachedVerdict> checked = new ConcurrentHashMap<>();
    private final Map<Integer, CompletableFuture<CachedVerdict>> pendingFutures = new ConcurrentHashMap<>();
    private final AtomicInteger roundRobinIndex = new AtomicInteger(0);
    private final List<Provider> providers = new ArrayList<>();
    private final Map<AnonymizerType, Object> reasonKickMessages = new EnumMap<>(AnonymizerType.class);

    private Semaphore semaphore;
    private int timeout;
    private int checksPerPlayer;
    private int blockThreshold;
    private long cleanCacheMillis;
    private long blockedCacheMillis;
    private long incompleteCacheMillis;

    public AntiVpnModule(Gatekeeper<?> gatekeeper) {
        super(gatekeeper, "AntiVpn");
    }

    @Override
    public boolean handlePreLogin(GeoConnection connection) {
        if (connection.isLocalhost() || this.providers.isEmpty() || this.checksPerPlayer <= 0) {
            return false;
        }

        // AntiVPN decisions are always scoped to the exact IP. ASN-wide caching was
        // a major false-positive multiplier and is intentionally not supported here.
        int id = connection.getAddressData();

        CachedVerdict cached = this.getCachedVerdict(id);
        if (cached != null) {
            return cached.blocked;
        }

        CompletableFuture<CachedVerdict> ownFuture = new CompletableFuture<>();
        CompletableFuture<CachedVerdict> existingFuture = this.pendingFutures.putIfAbsent(id, ownFuture);
        if (existingFuture != null) {
            return existingFuture.join().blocked;
        }

        boolean acquired = false;
        try {
            if (this.semaphore != null) {
                this.semaphore.acquire();
                acquired = true;
            }

            CachedVerdict verdict = this.checkAddress(connection.getAddress().getHostAddress());
            this.checked.put(id, verdict);
            ownFuture.complete(verdict);
            return verdict.blocked;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            CachedVerdict failOpen = CachedVerdict.clean(System.currentTimeMillis() + this.incompleteCacheMillis);
            this.checked.put(id, failOpen);
            ownFuture.complete(failOpen);
            return false;
        } catch (Throwable ex) {
            getGatekeeper().logger().log(Level.FINE, "AntiVPN check failed; allowing connection", ex);
            CachedVerdict failOpen = CachedVerdict.clean(System.currentTimeMillis() + this.incompleteCacheMillis);
            this.checked.put(id, failOpen);
            ownFuture.complete(failOpen);
            return false;
        } finally {
            this.pendingFutures.remove(id, ownFuture);
            if (acquired && this.semaphore != null) {
                this.semaphore.release();
            }
        }
    }

    private CachedVerdict checkAddress(String address) {
        int totalProviders = this.providers.size();
        int selectedCount = Math.min(this.checksPerPlayer, totalProviders);
        int startIdx = this.roundRobinIndex.getAndUpdate(i -> (i + 1) % totalProviders);

        List<CompletableFuture<ProviderResult>> futures = new ArrayList<>(selectedCount);
        for (int i = 0; i < selectedCount; i++) {
            Provider provider = this.providers.get((startIdx + i) % totalProviders);
            futures.add(this.performSingleCheck(provider, address));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        int successfulChecks = 0;
        List<java.util.Set<AnonymizerType>> signals = new ArrayList<>(futures.size());
        for (CompletableFuture<ProviderResult> future : futures) {
            ProviderResult result = future.join();
            if (!result.available) continue;
            successfulChecks++;
            signals.add(result.signals);
        }

        AnonymizerConsensus.Decision decision = AnonymizerConsensus.decide(signals, this.blockThreshold);
        long now = System.currentTimeMillis();
        long ttl;
        if (decision.isBlocked()) {
            ttl = this.blockedCacheMillis;
        } else if (successfulChecks >= this.blockThreshold) {
            ttl = this.cleanCacheMillis;
        } else {
            // Temporary API outages/rate limits should not become long-lived clean verdicts.
            ttl = this.incompleteCacheMillis;
        }

        return new CachedVerdict(
                decision.isBlocked(),
                decision.getReason(),
                now + ttl
        );
    }

    private CompletableFuture<ProviderResult> performSingleCheck(Provider provider, String address) {
        String urlStr = provider.url.replace("%address%", address);

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(urlStr))
                .timeout(Duration.ofMillis(this.timeout))
                .GET();

        provider.headers.forEach(requestBuilder::header);

        return TaskManager.INSTANCE.getHttpClient()
                .sendAsync(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != 200) {
                        getGatekeeper().logger().log(
                                Level.FINE,
                                "AntiVPN provider {0} returned HTTP {1}; ignoring provider for this check",
                                new Object[]{provider.name, response.statusCode()}
                        );
                        return ProviderResult.unavailable();
                    }
                    return ProviderResult.available(provider.evaluate(response.body()));
                })
                .exceptionally(ex -> {
                    getGatekeeper().logger().log(Level.FINE, "AntiVPN provider failed: " + provider.name, ex);
                    return ProviderResult.unavailable();
                });
    }

    private CachedVerdict getCachedVerdict(int id) {
        CachedVerdict verdict = this.checked.get(id);
        if (verdict == null) return null;
        if (verdict.expiresAtMillis > System.currentTimeMillis()) return verdict;
        this.checked.remove(id, verdict);
        return null;
    }

    @Override
    public Object getKickMessage(GeoConnection connection) {
        CachedVerdict verdict = this.getCachedVerdict(connection.getAddressData());
        if (verdict == null || verdict.reason == null) {
            return super.getKickMessage(connection);
        }
        return this.reasonKickMessages.getOrDefault(verdict.reason, super.getKickMessage(connection));
    }

    @Override
    public boolean handlePostLogin(GeoConnection connection) {
        return false;
    }

    @Override
    public boolean handleDisconnect(GeoConnection connection) {
        return false;
    }

    @Override
    public boolean load() throws IOException {
        this.timeout = positiveOrDefault(this.getConfig().getInt("timeout"), 2500);
        this.checksPerPlayer = positiveOrDefault(this.getConfig().getInt("checks_per_player"), 3);
        this.blockThreshold = positiveOrDefault(this.getConfig().getInt("block_threshold"), 2);

        int maxConcurrentChecks = this.getConfig().getInt("max_concurrent_checks");
        this.semaphore = maxConcurrentChecks > 0 ? new Semaphore(maxConcurrentChecks) : null;

        this.cleanCacheMillis = minutesToMillis(positiveOrDefault(this.getConfig().getInt("cache_clean_minutes"), 30));
        this.blockedCacheMillis = minutesToMillis(positiveOrDefault(this.getConfig().getInt("cache_blocked_minutes"), 15));
        this.incompleteCacheMillis = secondsToMillis(positiveOrDefault(this.getConfig().getInt("cache_incomplete_seconds"), 60));

        this.reasonKickMessages.clear();
        for (AnonymizerType type : AnonymizerType.values()) {
            this.reasonKickMessages.put(
                    type,
                    this.loadMessage("kick_reasons." + type.getConfigKey(), super.getKickMessage(null))
            );
        }

        this.providers.clear();
        boolean needSave = false;
        Section checks = this.getConfig().getSection("checks");
        if (checks == null) return true;

        for (Object key : checks.getKeys()) {
            Section section = this.getConfig().getSection("checks." + key);
            if (section == null) continue;

            String url = section.getString("url");
            if (url == null || url.isBlank() || !section.getBoolean("enabled")) continue;

            if (section.isString("condition")) {
                section.set("condition.json", section.getString("condition"));
                needSave = true;
            }

            Map<String, String> headers = section.getStringList("headers", Collections.emptyList()).stream()
                    .map(header -> header.split(":", 2))
                    .filter(parts -> parts.length == 2)
                    .collect(Collectors.toMap(
                            parts -> parts[0].trim(),
                            parts -> parts[1].trim(),
                            (existing, replacement) -> replacement
                    ));

            Map<AnonymizerType, AbstractConditionSet> conditions = this.loadSignalConditions(section);
            if (conditions.isEmpty()) {
                AbstractConditionSet legacyCondition = this.loadLegacyCondition(section);
                if (legacyCondition != null) {
                    conditions.put(AnonymizerType.ANONYMIZER, legacyCondition);
                }
            }

            if (!conditions.isEmpty()) {
                this.providers.add(new Provider(Objects.toString(key), url, headers, conditions));
            }
        }

        if (needSave) {
            this.getYamlDocument().save();
        }

        return true;
    }

    private Map<AnonymizerType, AbstractConditionSet> loadSignalConditions(Section providerSection) {
        Map<AnonymizerType, AbstractConditionSet> result = new EnumMap<>(AnonymizerType.class);
        Section signals = providerSection.getSection("signals");
        if (signals == null) return result;

        for (Object signalKey : signals.getKeys()) {
            AnonymizerType type = AnonymizerType.fromConfigKey(Objects.toString(signalKey));
            if (type == null) continue;

            Section signalSection = signals.getSection(Objects.toString(signalKey));
            AbstractConditionSet condition = this.compileCondition(signalSection, "");
            if (condition != null) result.put(type, condition);
        }
        return result;
    }

    private AbstractConditionSet loadLegacyCondition(Section providerSection) {
        return this.compileCondition(providerSection, "condition.");
    }

    private AbstractConditionSet compileCondition(Section section, String prefix) {
        if (section == null) return null;

        if (section.contains(prefix + "json")) {
            String expression = section.getString(prefix + "json");
            if (expression != null) return JsonConditionSet.compile(expression);
        }
        if (section.contains(prefix + "text")) {
            String expression = section.getString(prefix + "text");
            if (expression != null) return TextConditionSet.compile(expression);
        }
        return null;
    }

    @Override
    public boolean unload() {
        CachedVerdict failOpen = CachedVerdict.clean(System.currentTimeMillis() + 1000L);
        this.pendingFutures.values().forEach(future -> future.complete(failOpen));
        this.pendingFutures.clear();
        this.checked.clear();
        this.providers.clear();
        this.reasonKickMessages.clear();
        this.semaphore = null;
        return true;
    }

    private static int positiveOrDefault(int value, int defaultValue) {
        return value > 0 ? value : defaultValue;
    }

    private static long minutesToMillis(int minutes) {
        return minutes * 60_000L;
    }

    private static long secondsToMillis(int seconds) {
        return seconds * 1000L;
    }

    private static final class CachedVerdict {
        private final boolean blocked;
        private final AnonymizerType reason;
        private final long expiresAtMillis;

        private CachedVerdict(boolean blocked, AnonymizerType reason, long expiresAtMillis) {
            this.blocked = blocked;
            this.reason = reason;
            this.expiresAtMillis = expiresAtMillis;
        }

        private static CachedVerdict clean(long expiresAtMillis) {
            return new CachedVerdict(false, null, expiresAtMillis);
        }
    }

    private static final class ProviderResult {
        private final boolean available;
        private final EnumSet<AnonymizerType> signals;

        private ProviderResult(boolean available, EnumSet<AnonymizerType> signals) {
            this.available = available;
            this.signals = signals;
        }

        private static ProviderResult unavailable() {
            return new ProviderResult(false, EnumSet.noneOf(AnonymizerType.class));
        }

        private static ProviderResult available(EnumSet<AnonymizerType> signals) {
            return new ProviderResult(true, signals);
        }
    }

    private static final class Provider {
        private final String name;
        private final String url;
        private final Map<String, String> headers;
        private final Map<AnonymizerType, AbstractConditionSet> conditions;

        private Provider(
                String name,
                String url,
                Map<String, String> headers,
                Map<AnonymizerType, AbstractConditionSet> conditions
        ) {
            this.name = name;
            this.url = url;
            this.headers = headers;
            this.conditions = conditions;
        }

        private EnumSet<AnonymizerType> evaluate(String body) {
            EnumSet<AnonymizerType> matches = EnumSet.noneOf(AnonymizerType.class);
            for (Map.Entry<AnonymizerType, AbstractConditionSet> entry : this.conditions.entrySet()) {
                if (entry.getValue().evaluate(body)) {
                    matches.add(entry.getKey());
                }
            }
            return matches;
        }
    }
}
