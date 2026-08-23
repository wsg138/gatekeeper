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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.stream.Collectors;

public class AntiVpnModule extends AbstractModule {
    private final Map<String, CachedVerdict> checked = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<CachedVerdict>> pendingFutures = new ConcurrentHashMap<>();
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
        if (connection.isLocalhost() || this.providers.isEmpty() || this.checksPerPlayer <= 0) return false;

        String key = connection.getAddressKey();
        CachedVerdict cached = this.getCachedVerdict(key);
        if (cached != null) return cached.blocked;

        CompletableFuture<CachedVerdict> ownFuture = new CompletableFuture<>();
        CompletableFuture<CachedVerdict> existingFuture = this.pendingFutures.putIfAbsent(key, ownFuture);
        if (existingFuture != null) {
            try {
                return existingFuture.get(this.timeout + 500L, TimeUnit.MILLISECONDS).blocked;
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return false;
            } catch (Exception ex) {
                return false;
            }
        }

        boolean acquired = false;
        try {
            if (this.semaphore != null) {
                acquired = this.semaphore.tryAcquire();
                if (!acquired) {
                    CachedVerdict failOpen = CachedVerdict.clean(
                            System.currentTimeMillis() + this.incompleteCacheMillis,
                            "check capacity exhausted; failed open"
                    );
                    this.checked.put(key, failOpen);
                    ownFuture.complete(failOpen);
                    return false;
                }
            }

            CachedVerdict verdict = this.checkAddress(connection.getAddressKey());
            this.checked.put(key, verdict);
            ownFuture.complete(verdict);
            return verdict.blocked;
        } catch (Throwable ex) {
            getGatekeeper().logger().log(Level.FINE, "AntiVPN check failed; allowing connection", ex);
            CachedVerdict failOpen = CachedVerdict.clean(
                    System.currentTimeMillis() + this.incompleteCacheMillis,
                    "check failed; failed open"
            );
            this.checked.put(key, failOpen);
            ownFuture.complete(failOpen);
            return false;
        } finally {
            this.pendingFutures.remove(key, ownFuture);
            if (acquired && this.semaphore != null) this.semaphore.release();
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
        List<String> providerDetails = new ArrayList<>(futures.size());
        for (CompletableFuture<ProviderResult> future : futures) {
            ProviderResult result = future.join();
            providerDetails.add(result.describe());
            if (!result.available) continue;
            successfulChecks++;
            signals.add(result.signals);
        }

        AnonymizerConsensus.Decision decision = AnonymizerConsensus.decide(signals, this.blockThreshold);
        long now = System.currentTimeMillis();
        long ttl = decision.isBlocked()
                ? this.blockedCacheMillis
                : (successfulChecks >= this.blockThreshold ? this.cleanCacheMillis : this.incompleteCacheMillis);

        return new CachedVerdict(
                decision.isBlocked(),
                decision.getReason(),
                now + ttl,
                String.join(", ", providerDetails)
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
                        return ProviderResult.unavailable(provider.name, "http_" + response.statusCode());
                    }
                    return ProviderResult.available(provider.name, provider.evaluate(response.body()));
                })
                .exceptionally(ex -> {
                    getGatekeeper().logger().log(Level.FINE, "AntiVPN provider failed: " + provider.name, ex);
                    return ProviderResult.unavailable(provider.name, "error");
                });
    }

    private CachedVerdict getCachedVerdict(String key) {
        CachedVerdict verdict = this.checked.get(key);
        if (verdict == null) return null;
        if (verdict.expiresAtMillis > System.currentTimeMillis()) return verdict;
        this.checked.remove(key, verdict);
        return null;
    }

    @Override
    public Object getKickMessage(GeoConnection connection) {
        if (connection == null) return super.getKickMessage(null);
        CachedVerdict verdict = this.getCachedVerdict(connection.getAddressKey());
        if (verdict == null || verdict.reason == null) return super.getKickMessage(connection);
        return this.reasonKickMessages.getOrDefault(verdict.reason, super.getKickMessage(connection));
    }

    @Override
    public String getDecisionCode(GeoConnection connection) {
        if (connection == null) return "antivpn";
        CachedVerdict verdict = this.getCachedVerdict(connection.getAddressKey());
        if (verdict == null || verdict.reason == null) return "antivpn";
        return verdict.reason.getConfigKey();
    }

    @Override
    public String getDecisionDetail(GeoConnection connection) {
        if (connection == null) return "";
        CachedVerdict verdict = this.getCachedVerdict(connection.getAddressKey());
        return verdict == null ? "" : verdict.detail;
    }

    @Override
    public boolean handlePostLogin(GeoConnection connection) { return false; }

    @Override
    public boolean handleDisconnect(GeoConnection connection) { return false; }

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
        Section checks = this.getConfig().getSection("checks");
        if (checks == null) return true;

        for (Object key : checks.getKeys()) {
            Section section = this.getConfig().getSection("checks." + key);
            if (section == null) continue;

            String url = section.getString("url");
            if (url == null || url.isBlank() || !section.getBoolean("enabled")) continue;

            Map<String, String> headers = section.getStringList("headers", Collections.emptyList()).stream()
                    .map(header -> header.split(":", 2))
                    .filter(parts -> parts.length == 2)
                    .collect(Collectors.toMap(
                            parts -> parts[0].trim(),
                            parts -> parts[1].trim(),
                            (existing, replacement) -> replacement
                    ));

            // The fork intentionally accepts only typed v2 signal definitions.
            // Legacy single boolean conditions often mixed hosting/abuse with VPN
            // evidence and are therefore ignored rather than trusted as blockers.
            Map<AnonymizerType, AbstractConditionSet> conditions = this.loadSignalConditions(section);
            if (!conditions.isEmpty()) {
                this.providers.add(new Provider(Objects.toString(key), url, headers, conditions));
            }
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
            AbstractConditionSet condition = this.compileCondition(signalSection);
            if (condition != null) result.put(type, condition);
        }
        return result;
    }

    private AbstractConditionSet compileCondition(Section section) {
        if (section == null) return null;
        if (section.contains("json")) {
            String expression = section.getString("json");
            if (expression != null) return JsonConditionSet.compile(expression);
        }
        if (section.contains("text")) {
            String expression = section.getString("text");
            if (expression != null) return TextConditionSet.compile(expression);
        }
        return null;
    }

    @Override
    public boolean unload() {
        CachedVerdict failOpen = CachedVerdict.clean(System.currentTimeMillis() + 1000L, "module unloading");
        this.pendingFutures.values().forEach(future -> future.complete(failOpen));
        this.pendingFutures.clear();
        this.checked.clear();
        this.providers.clear();
        this.reasonKickMessages.clear();
        this.semaphore = null;
        return true;
    }

    private static int positiveOrDefault(int value, int defaultValue) { return value > 0 ? value : defaultValue; }
    private static long minutesToMillis(int minutes) { return minutes * 60_000L; }
    private static long secondsToMillis(int seconds) { return seconds * 1000L; }

    private static final class CachedVerdict {
        private final boolean blocked;
        private final AnonymizerType reason;
        private final long expiresAtMillis;
        private final String detail;

        private CachedVerdict(boolean blocked, AnonymizerType reason, long expiresAtMillis, String detail) {
            this.blocked = blocked;
            this.reason = reason;
            this.expiresAtMillis = expiresAtMillis;
            this.detail = detail == null ? "" : detail;
        }

        private static CachedVerdict clean(long expiresAtMillis, String detail) {
            return new CachedVerdict(false, null, expiresAtMillis, detail);
        }
    }

    private static final class ProviderResult {
        private final String provider;
        private final boolean available;
        private final EnumSet<AnonymizerType> signals;
        private final String status;

        private ProviderResult(String provider, boolean available, EnumSet<AnonymizerType> signals, String status) {
            this.provider = provider;
            this.available = available;
            this.signals = signals;
            this.status = status;
        }

        private static ProviderResult unavailable(String provider, String status) {
            return new ProviderResult(provider, false, EnumSet.noneOf(AnonymizerType.class), status);
        }

        private static ProviderResult available(String provider, EnumSet<AnonymizerType> signals) {
            return new ProviderResult(provider, true, signals, "ok");
        }

        private String describe() {
            if (!this.available) return this.provider + "=unavailable(" + this.status + ")";
            if (this.signals.isEmpty()) return this.provider + "=clean";
            return this.provider + "=" + this.signals.stream()
                    .map(AnonymizerType::getConfigKey)
                    .sorted()
                    .collect(Collectors.joining("+"));
        }
    }

    private static final class Provider {
        private final String name;
        private final String url;
        private final Map<String, String> headers;
        private final Map<AnonymizerType, AbstractConditionSet> conditions;

        private Provider(String name, String url, Map<String, String> headers, Map<AnonymizerType, AbstractConditionSet> conditions) {
            this.name = name;
            this.url = url;
            this.headers = headers;
            this.conditions = conditions;
        }

        private EnumSet<AnonymizerType> evaluate(String body) {
            EnumSet<AnonymizerType> matches = EnumSet.noneOf(AnonymizerType.class);
            for (Map.Entry<AnonymizerType, AbstractConditionSet> entry : this.conditions.entrySet()) {
                if (entry.getValue().evaluate(body)) matches.add(entry.getKey());
            }
            return matches;
        }
    }
}
