package xyz.lychee.gatekeeper.shared.manager;

import dev.dejvokep.boostedyaml.YamlDocument;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;
import xyz.lychee.gatekeeper.shared.objects.GeoRange;
import xyz.lychee.gatekeeper.shared.security.RiskSignalType;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;

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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Downloads reputation-only intelligence. Matches from this manager never directly deny a connection. */
public class ReputationManager extends AbstractManager implements Runnable {
    public static final ReputationManager INSTANCE = new ReputationManager();

    private static final Pattern ASN_PATTERN = Pattern.compile("(?i)\\b(?:AS)?(\\d{3,10})\\b");
    private static final Pattern IP_PATTERN = Pattern.compile(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?:/(\\d{1,2}))?"
    );
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(8);

    private static final RiskSignalType[] IP_TYPES = {
            RiskSignalType.REPUTATION_VPN_IP,
            RiskSignalType.REPUTATION_PROXY_IP,
            RiskSignalType.REPUTATION_HOSTING_IP,
            RiskSignalType.REPUTATION_SCANNER_IP,
            RiskSignalType.REPUTATION_ABUSE_IP
    };

    private static final RiskSignalType[] ASN_TYPES = {
            RiskSignalType.REPUTATION_VPN_ASN,
            RiskSignalType.REPUTATION_HOSTING_ASN,
            RiskSignalType.REPUTATION_SCANNER_ASN
    };

    private final Map<RiskSignalType, List<String>> sources = new EnumMap<>(RiskSignalType.class);
    private final AtomicLong generation = new AtomicLong();
    private volatile Map<RiskSignalType, IpMatcher> ipMatchers = Collections.emptyMap();
    private volatile Map<RiskSignalType, IntOpenHashSet> asnMatchers = Collections.emptyMap();
    private volatile boolean active;
    private Logger logger;

    @Override
    public boolean load(Gatekeeper<?> plugin) {
        this.logger = plugin.logger();
        this.active = true;
        long current = this.loadSources();
        this.refresh(current).join();
        return true;
    }

    @Override
    public boolean unload(Gatekeeper<?> plugin) {
        this.active = false;
        this.generation.incrementAndGet();
        synchronized (this.sources) {
            this.sources.clear();
        }
        this.ipMatchers = Collections.emptyMap();
        this.asnMatchers = Collections.emptyMap();
        return true;
    }

    @Override
    public boolean reload(Gatekeeper<?> plugin) {
        long current = this.loadSources();
        // Configuration changes fail open while new scoring-only data downloads.
        this.ipMatchers = Collections.emptyMap();
        this.asnMatchers = Collections.emptyMap();
        this.refresh(current);
        return true;
    }

    @Override
    public void run() {
        if (this.active) this.refresh(this.generation.get());
    }

    private long loadSources() {
        YamlDocument yaml = ConfigManager.INSTANCE.getYaml();
        synchronized (this.sources) {
            this.sources.clear();
            for (RiskSignalType type : IP_TYPES) {
                this.sources.put(type, new ArrayList<>(
                        yaml.getStringList("main.reputation.sources." + type.getConfigKey())
                ));
            }
            for (RiskSignalType type : ASN_TYPES) {
                this.sources.put(type, new ArrayList<>(
                        yaml.getStringList("main.reputation.sources." + type.getConfigKey())
                ));
            }
        }
        this.active = true;
        return this.generation.incrementAndGet();
    }

    public CompletableFuture<Void> refresh() {
        return this.refresh(this.generation.get());
    }

    private CompletableFuture<Void> refresh(long refreshGeneration) {
        Map<RiskSignalType, List<String>> sourceSnapshot = new EnumMap<>(RiskSignalType.class);
        synchronized (this.sources) {
            for (Map.Entry<RiskSignalType, List<String>> entry : this.sources.entrySet()) {
                sourceSnapshot.put(entry.getKey(), new ArrayList<>(entry.getValue()));
            }
        }

        Map<RiskSignalType, IpMatcher> nextIp = new ConcurrentHashMap<>();
        Map<RiskSignalType, IntOpenHashSet> nextAsn = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (RiskSignalType type : IP_TYPES) {
            futures.add(this.downloadIpMatcher(type, sourceSnapshot.getOrDefault(type, Collections.emptyList()))
                    .thenAccept(matcher -> {
                        if (matcher != null) nextIp.put(type, matcher);
                    }));
        }
        for (RiskSignalType type : ASN_TYPES) {
            futures.add(this.downloadAsnMatcher(type, sourceSnapshot.getOrDefault(type, Collections.emptyList()))
                    .thenAccept(matcher -> {
                        if (matcher != null) nextAsn.put(type, matcher);
                    }));
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenRun(() -> {
                    if (!this.active || this.generation.get() != refreshGeneration) return;

                    Map<RiskSignalType, IpMatcher> ipSnapshot = new EnumMap<>(RiskSignalType.class);
                    ipSnapshot.putAll(this.ipMatchers);
                    ipSnapshot.putAll(nextIp);

                    Map<RiskSignalType, IntOpenHashSet> asnSnapshot = new EnumMap<>(RiskSignalType.class);
                    asnSnapshot.putAll(this.asnMatchers);
                    asnSnapshot.putAll(nextAsn);

                    this.ipMatchers = Collections.unmodifiableMap(ipSnapshot);
                    this.asnMatchers = Collections.unmodifiableMap(asnSnapshot);

                    int ipEntries = 0;
                    for (IpMatcher matcher : this.ipMatchers.values()) ipEntries += matcher.sizeEstimate();
                    int asnEntries = 0;
                    for (IntOpenHashSet set : this.asnMatchers.values()) asnEntries += set.size();
                    this.logger.info(" &8• &rRefreshed reputation intelligence: "
                            + ipEntries + " IP/range entries and " + asnEntries + " ASN entries.");
                });
    }

    public EnumSet<RiskSignalType> assess(int ip, int asn) {
        EnumSet<RiskSignalType> matches = EnumSet.noneOf(RiskSignalType.class);

        Map<RiskSignalType, IpMatcher> ipSnapshot = this.ipMatchers;
        for (RiskSignalType type : IP_TYPES) {
            IpMatcher matcher = ipSnapshot.get(type);
            if (matcher != null && matcher.contains(ip)) matches.add(type);
        }

        if (asn > 0) {
            Map<RiskSignalType, IntOpenHashSet> asnSnapshot = this.asnMatchers;
            for (RiskSignalType type : ASN_TYPES) {
                IntOpenHashSet matcher = asnSnapshot.get(type);
                if (matcher != null && matcher.contains(asn)) matches.add(type);
            }
        }
        return matches;
    }

    private CompletableFuture<IpMatcher> downloadIpMatcher(RiskSignalType type, List<String> typeSources) {
        if (typeSources.isEmpty()) return CompletableFuture.completedFuture(IpMatcher.empty());

        IntOpenHashSet exact = new IntOpenHashSet();
        List<GeoRange<Void>> ranges = new ArrayList<>();
        AtomicInteger successes = new AtomicInteger();
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (String source : typeSources) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(source))
                        .timeout(REQUEST_TIMEOUT)
                        .header("User-Agent", "Gatekeeper-Enthusia/1.7")
                        .GET()
                        .build();

                futures.add(TaskManager.INSTANCE.getHttpClient()
                        .sendAsync(request, HttpResponse.BodyHandlers.ofString())
                        .thenAccept(response -> {
                            if (response.statusCode() != 200) return;
                            successes.incrementAndGet();

                            IntOpenHashSet localExact = new IntOpenHashSet();
                            List<GeoRange<Void>> localRanges = new ArrayList<>();
                            parseIpBody(response.body(), localExact, localRanges);
                            synchronized (exact) {
                                exact.addAll(localExact);
                            }
                            synchronized (ranges) {
                                ranges.addAll(localRanges);
                            }
                        })
                        .exceptionally(ex -> {
                            this.logger.log(Level.FINE, "Reputation source failed: " + source, ex);
                            return null;
                        }));
            } catch (RuntimeException ex) {
                this.logger.log(Level.FINE, "Invalid reputation source: " + source, ex);
            }
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenApply(ignored -> {
                    if (successes.get() == 0) return null;
                    return new IpMatcher(exact, mergeRanges(ranges));
                });
    }

    private CompletableFuture<IntOpenHashSet> downloadAsnMatcher(RiskSignalType type, List<String> typeSources) {
        if (typeSources.isEmpty()) return CompletableFuture.completedFuture(new IntOpenHashSet());

        IntOpenHashSet output = new IntOpenHashSet();
        AtomicInteger successes = new AtomicInteger();
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (String source : typeSources) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(source))
                        .timeout(REQUEST_TIMEOUT)
                        .header("User-Agent", "Gatekeeper-Enthusia/1.7")
                        .GET()
                        .build();

                futures.add(TaskManager.INSTANCE.getHttpClient()
                        .sendAsync(request, HttpResponse.BodyHandlers.ofString())
                        .thenAccept(response -> {
                            if (response.statusCode() != 200) return;
                            successes.incrementAndGet();

                            IntOpenHashSet local = new IntOpenHashSet();
                            for (String line : response.body().split("\\R")) {
                                String clean = stripComment(line);
                                if (clean.isEmpty()) continue;
                                Matcher matcher = ASN_PATTERN.matcher(clean);
                                while (matcher.find()) {
                                    try {
                                        local.add(Integer.parseInt(matcher.group(1)));
                                    } catch (NumberFormatException ignored) {}
                                }
                            }
                            synchronized (output) {
                                output.addAll(local);
                            }
                        })
                        .exceptionally(ex -> {
                            this.logger.log(Level.FINE, "Reputation ASN source failed: " + source, ex);
                            return null;
                        }));
            } catch (RuntimeException ex) {
                this.logger.log(Level.FINE, "Invalid reputation ASN source: " + source, ex);
            }
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenApply(ignored -> successes.get() == 0 ? null : output);
    }

    private static void parseIpBody(String body, IntOpenHashSet exact, List<GeoRange<Void>> ranges) {
        for (String line : body.split("\\R")) {
            String clean = stripComment(line);
            if (clean.isEmpty()) continue;

            Matcher matcher = IP_PATTERN.matcher(clean);
            while (matcher.find()) {
                String ipString = matcher.group(1);
                String prefixString = matcher.group(2);
                if (!AddressUtils.isIpv4(ipString)) continue;

                int ip = AddressUtils.ipv4ToInt(ipString);
                if ((ip >>> 24) == 0x7F) continue;

                if (prefixString == null) {
                    exact.add(ip);
                    continue;
                }

                int prefix;
                try {
                    prefix = Integer.parseInt(prefixString);
                } catch (NumberFormatException ignored) {
                    continue;
                }
                if (prefix < 0 || prefix > 32) continue;

                int mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                int start = ip & mask;
                int end = start | ~mask;
                if (overlapsLoopback(start, end)) continue;
                if (start == end) exact.add(start);
                else ranges.add(new GeoRange<>(start, end, null));
            }
        }
    }

    private static String stripComment(String line) {
        int comment = line.indexOf('#');
        return (comment >= 0 ? line.substring(0, comment) : line).trim();
    }

    private static boolean overlapsLoopback(int start, int end) {
        int loopbackStart = 0x7F000000;
        int loopbackEnd = 0x7FFFFFFF;
        return Integer.compareUnsigned(start, loopbackEnd) <= 0
                && Integer.compareUnsigned(end, loopbackStart) >= 0;
    }

    private static List<GeoRange<Void>> mergeRanges(List<GeoRange<Void>> input) {
        if (input.isEmpty()) return Collections.emptyList();
        List<GeoRange<Void>> ranges = new ArrayList<>(input);
        ranges.sort((a, b) -> Integer.compareUnsigned(a.getStart(), b.getStart()));

        List<GeoRange<Void>> merged = new ArrayList<>();
        GeoRange<Void> current = ranges.get(0);
        for (int i = 1; i < ranges.size(); i++) {
            GeoRange<Void> next = ranges.get(i);
            boolean overlaps = Integer.compareUnsigned(next.getStart(), current.getEnd()) <= 0;
            boolean adjacent = current.getEnd() != -1 && next.getStart() == current.getEnd() + 1;
            if (overlaps || adjacent) {
                int end = Integer.compareUnsigned(current.getEnd(), next.getEnd()) >= 0
                        ? current.getEnd() : next.getEnd();
                current = new GeoRange<>(current.getStart(), end, null);
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);
        return Collections.unmodifiableList(merged);
    }

    private static final class IpMatcher {
        private final IntOpenHashSet exact;
        private final List<GeoRange<Void>> ranges;

        private IpMatcher(IntOpenHashSet exact, List<GeoRange<Void>> ranges) {
            this.exact = exact;
            this.ranges = ranges;
        }

        private static IpMatcher empty() {
            return new IpMatcher(new IntOpenHashSet(), Collections.emptyList());
        }

        private int sizeEstimate() {
            return this.exact.size() + this.ranges.size();
        }

        private boolean contains(int ip) {
            if (this.exact.contains(ip)) return true;

            int low = 0;
            int high = this.ranges.size() - 1;
            while (low <= high) {
                int mid = (low + high) >>> 1;
                GeoRange<Void> range = this.ranges.get(mid);
                if (Integer.compareUnsigned(ip, range.getStart()) < 0) {
                    high = mid - 1;
                } else if (Integer.compareUnsigned(ip, range.getEnd()) > 0) {
                    low = mid + 1;
                } else {
                    return true;
                }
            }
            return false;
        }
    }
}
