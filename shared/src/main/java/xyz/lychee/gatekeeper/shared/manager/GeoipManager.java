package xyz.lychee.gatekeeper.shared.manager;

import dev.dejvokep.boostedyaml.YamlDocument;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import lombok.Getter;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;
import xyz.lychee.gatekeeper.shared.objects.BinaryGeoIPDatabase;
import xyz.lychee.gatekeeper.shared.objects.GeoRange;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;
import xyz.lychee.gatekeeper.shared.util.SerializeUtils;
import xyz.lychee.gatekeeper.shared.util.TimingUtil;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Getter
public class GeoipManager extends AbstractManager implements Runnable {
    public static final GeoipManager INSTANCE = new GeoipManager();
    private static final Pattern ASN_PATTERN = Pattern.compile("(?i)\\b(?:AS)?(\\d{3,10})\\b");
    private static final Pattern IP_PATTERN = Pattern
            .compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?:/(\\d{1,2}))?");
    private static final Duration SOURCE_TIMEOUT = Duration.ofSeconds(10);

    private final List<String> asnSource = new ArrayList<>();
    private final List<String> proxySources = new ArrayList<>();
    private final BinaryGeoIPDatabase database = new BinaryGeoIPDatabase();
    private volatile IntOpenHashSet blacklistedAsns = new IntOpenHashSet();
    private volatile IntOpenHashSet blacklistedProxies = new IntOpenHashSet();
    private volatile List<GeoRange<Void>> blacklistedProxyRanges = Collections.emptyList();
    private Logger logger;
    private Path geoDataPath;
    private Path asnDataPath;
    private Path proxyDataPath;
    private Path proxyRangesDataPath;

    @Override
    public boolean load(Gatekeeper<?> plugin) throws IOException {
        this.logger = plugin.logger();
        this.geoDataPath = new File(plugin.dataFolder(), "geodata.ldb").toPath();
        this.asnDataPath = new File(plugin.dataFolder(), "asn_data.bin").toPath();
        this.proxyDataPath = new File(plugin.dataFolder(), "proxy_data.bin").toPath();
        this.proxyRangesDataPath = new File(plugin.dataFolder(), "proxy_ranges_data.bin").toPath();
        this.loadSources();

        boolean migrationComplete = Files.exists(plugin.dataFolder().toPath().resolve(MigrationManager.MARKER));
        this.download(true, !migrationComplete).join();
        return true;
    }

    @Override
    public boolean unload(Gatekeeper<?> gatekeeper) {
        return true;
    }

    @Override
    public boolean reload(Gatekeeper<?> gatekeeper) {
        this.loadSources();

        // Hard-list policy must never keep stale decisions after a config reload.
        // Clear first, then repopulate asynchronously from the newly loaded sources.
        this.blacklistedAsns = new IntOpenHashSet();
        this.blacklistedProxies = new IntOpenHashSet();
        this.blacklistedProxyRanges = Collections.emptyList();
        this.download(false, true);
        return true;
    }

    private void loadSources() {
        YamlDocument yaml = ConfigManager.INSTANCE.getYaml();
        synchronized (this.asnSource) {
            this.asnSource.clear();
            this.asnSource.addAll(yaml.getStringList("main.auto_updater.asn_sources"));
            Collections.shuffle(this.asnSource);
        }
        synchronized (this.proxySources) {
            this.proxySources.clear();
            this.proxySources.addAll(yaml.getStringList("main.auto_updater.proxy_sources"));
            Collections.shuffle(this.proxySources);
        }
    }

    private boolean needUpdate(Path dataFile, long amount, ChronoUnit unit) {
        if (Files.notExists(dataFile)) return true;
        try {
            Instant updateThreshold = Instant.now().minus(amount, unit);
            Instant fileModified = Files.getLastModifiedTime(dataFile).toInstant();
            return fileModified.compareTo(updateThreshold) < 0;
        } catch (IOException ignored) {
            return true;
        }
    }

    @Override
    public void run() {
        this.download(false, false);
    }

    public CompletableFuture<Void> download(boolean firstLoad) {
        return this.download(firstLoad, false);
    }

    private CompletableFuture<Void> download(boolean firstLoad, boolean forceNetworkLists) {
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        boolean geoExists = Files.exists(this.geoDataPath);
        boolean geoStale = this.needUpdate(this.geoDataPath, 12, ChronoUnit.HOURS);
        if (firstLoad && geoExists) {
            CompletableFuture<TimingUtil> geo = this.database.load(this.logger, this.geoDataPath)
                    .thenApply(t -> {
                        if (t != null) {
                            this.logger.info(" &8• &rLoaded " + this.database.getCountryRecordCount() + " country and "
                                    + this.database.getAsnRecordCount() + " asn ranges in " + t.stop() + "!");
                        }
                        return t;
                    });
            if (geoStale) {
                geo = geo.thenCompose(ignored -> this.database.update(this.logger, this.geoDataPath));
            }
            futures.add(geo.thenAccept(ignored -> {}));
        } else if (geoStale) {
            this.logger.info(" &8• &rDownloading and building GeoIP database...");
            futures.add(this.database.update(this.logger, this.geoDataPath)
                    .thenAccept(t -> this.logger.info(" &8• &rGeoIP database refresh finished in " + t.stop() + "!")));
        }

        boolean asnRefresh = forceNetworkLists || this.needUpdate(this.asnDataPath, 12, ChronoUnit.HOURS);
        if (asnRefresh) {
            List<String> sources;
            synchronized (this.asnSource) {
                sources = new ArrayList<>(this.asnSource);
            }
            this.logger.info(" &8• &rRefreshing suspicious ASNs from " + sources.size() + " sources...");
            futures.add(this.downloadFromSources(
                    sources,
                    this.asnDataPath,
                    line -> {
                        int commentIdx = line.indexOf('#');
                        String uncommented = (commentIdx != -1 ? line.substring(0, commentIdx) : line).trim();
                        if (uncommented.isEmpty()) return null;
                        Matcher matcher = ASN_PATTERN.matcher(uncommented);
                        List<Integer> asns = new ArrayList<>();
                        while (matcher.find()) asns.add(Integer.parseInt(matcher.group(1)));
                        return asns;
                    },
                    outputSet -> this.blacklistedAsns = outputSet
            ).thenAccept(t -> this.logger.info(" &8• &rLoaded " + this.blacklistedAsns.size() + " hard ASN entries.")));
        } else if (firstLoad) {
            futures.add(this.loadFromFile(this.asnDataPath, outputSet -> this.blacklistedAsns = outputSet)
                    .thenAccept(t -> this.logger.info(" &8• &rLoaded " + this.blacklistedAsns.size() + " hard ASN entries.")));
        }

        boolean proxyRefresh = forceNetworkLists
                || this.needUpdate(this.proxyDataPath, 1, ChronoUnit.HOURS)
                || this.needUpdate(this.proxyRangesDataPath, 1, ChronoUnit.HOURS);
        if (proxyRefresh) {
            List<String> sources;
            synchronized (this.proxySources) {
                sources = new ArrayList<>(this.proxySources);
            }
            this.logger.info(" &8• &rRefreshing hard-block IPs from " + sources.size() + " sources...");
            futures.add(this.downloadProxies(sources).thenAccept(timing ->
                    this.logger.info(" &8• &rLoaded " + this.blacklistedProxies.size()
                            + " hard-block IPs and " + this.blacklistedProxyRanges.size() + " ranges in " + timing.stop() + "!")));
        } else if (firstLoad) {
            futures.add(this.loadFromFile(this.proxyDataPath, outputSet -> this.blacklistedProxies = outputSet)
                    .thenCombine(this.loadProxyRangesFromFile(), (t1, t2) -> t1)
                    .thenAccept(timing -> this.logger.info(" &8• &rLoaded " + this.blacklistedProxies.size()
                            + " hard-block IPs and " + this.blacklistedProxyRanges.size() + " ranges.")));
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    public CompletableFuture<TimingUtil> downloadFromSources(
            List<String> sources,
            Path outputPath,
            Function<String, Collection<Integer>> parser,
            Consumer<IntOpenHashSet> consumer) {
        IntOpenHashSet outputSet = new IntOpenHashSet();
        TimingUtil timing = TimingUtil.startNew();
        List<CompletableFuture<Void>> requests = new ArrayList<>();

        for (String source : sources) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(source))
                        .timeout(SOURCE_TIMEOUT)
                        .header("User-Agent", "Gatekeeper-Enthusia/1.7")
                        .GET()
                        .build();
                requests.add(TaskManager.INSTANCE.getHttpClient().sendAsync(request, HttpResponse.BodyHandlers.ofString())
                        .thenAccept(response -> {
                            if (response.statusCode() != 200) {
                                this.logger.warning("Received " + response.statusCode() + " from source: " + source);
                                return;
                            }
                            IntOpenHashSet localSet = new IntOpenHashSet();
                            for (String line : response.body().split("\\R")) {
                                Collection<Integer> parsed = parser.apply(line);
                                if (parsed != null && !parsed.isEmpty()) localSet.addAll(parsed);
                            }
                            synchronized (outputSet) {
                                outputSet.addAll(localSet);
                            }
                        })
                        .exceptionally(ex -> {
                            this.logger.log(Level.WARNING, "Network-intelligence source failed: " + source, ex);
                            return null;
                        }));
            } catch (RuntimeException ex) {
                this.logger.log(Level.WARNING, "Invalid network-intelligence source: " + source, ex);
            }
        }

        return CompletableFuture.allOf(requests.toArray(new CompletableFuture[0]))
                .thenApplyAsync(v -> {
                    try {
                        Files.write(outputPath, SerializeUtils.serialize(outputSet));
                    } catch (IOException ex) {
                        this.logger.log(Level.SEVERE, "Failed to write data to " + outputPath, ex);
                    }
                    consumer.accept(outputSet);
                    return timing;
                }, TaskManager.INSTANCE.getAsyncExecutor());
    }

    private CompletableFuture<TimingUtil> downloadProxies(List<String> sources) {
        IntOpenHashSet outputSet = new IntOpenHashSet();
        List<GeoRange<Void>> outputRanges = new ArrayList<>();
        TimingUtil timing = TimingUtil.startNew();
        List<CompletableFuture<Void>> requests = new ArrayList<>();

        for (String source : sources) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(source))
                        .timeout(SOURCE_TIMEOUT)
                        .header("User-Agent", "Gatekeeper-Enthusia/1.7")
                        .GET()
                        .build();
                requests.add(TaskManager.INSTANCE.getHttpClient().sendAsync(request, HttpResponse.BodyHandlers.ofString())
                        .thenAccept(response -> {
                            if (response.statusCode() != 200) {
                                this.logger.warning("Received " + response.statusCode() + " from source: " + source);
                                return;
                            }

                            IntOpenHashSet localSet = new IntOpenHashSet();
                            List<GeoRange<Void>> localRanges = new ArrayList<>();
                            for (String line : response.body().split("\\R")) {
                                int commentIdx = line.indexOf('#');
                                String uncommented = (commentIdx != -1 ? line.substring(0, commentIdx) : line).trim();
                                if (uncommented.isEmpty()) continue;
                                Matcher matcher = IP_PATTERN.matcher(uncommented);
                                while (matcher.find()) {
                                    String ipStr = matcher.group(1);
                                    String cidrStr = matcher.group(2);
                                    if (!AddressUtils.isIpv4(ipStr)) continue;
                                    int ip = AddressUtils.ipv4ToInt(ipStr);

                                    if (cidrStr == null) {
                                        if ((ip >>> 24) != 0x7F) localSet.add(ip);
                                        continue;
                                    }

                                    int prefix;
                                    try {
                                        prefix = Integer.parseInt(cidrStr);
                                    } catch (NumberFormatException ignored) {
                                        continue;
                                    }
                                    if (prefix < 0 || prefix > 32) continue;

                                    int mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                                    int startIp = ip & mask;
                                    int endIp = startIp | ~mask;
                                    if (overlapsLoopback(startIp, endIp)) continue;
                                    if (startIp == endIp) localSet.add(startIp);
                                    else localRanges.add(new GeoRange<>(startIp, endIp, null));
                                }
                            }

                            synchronized (outputSet) {
                                outputSet.addAll(localSet);
                            }
                            synchronized (outputRanges) {
                                outputRanges.addAll(localRanges);
                            }
                        })
                        .exceptionally(ex -> {
                            this.logger.log(Level.WARNING, "Hard-block source failed: " + source, ex);
                            return null;
                        }));
            } catch (RuntimeException ex) {
                this.logger.log(Level.WARNING, "Invalid hard-block source: " + source, ex);
            }
        }

        return CompletableFuture.allOf(requests.toArray(new CompletableFuture[0]))
                .thenApplyAsync(v -> {
                    List<GeoRange<Void>> mergedRanges = mergeRanges(outputRanges);
                    try {
                        Files.write(this.proxyDataPath, SerializeUtils.serialize(outputSet));
                        ByteBuffer buffer = ByteBuffer.allocate(mergedRanges.size() * 8);
                        for (GeoRange<Void> range : mergedRanges) {
                            buffer.putInt(range.getStart());
                            buffer.putInt(range.getEnd());
                        }
                        Files.write(this.proxyRangesDataPath, buffer.array());
                    } catch (IOException ex) {
                        this.logger.log(Level.SEVERE, "Failed to write hard-block cache", ex);
                    }
                    this.blacklistedProxies = outputSet;
                    this.blacklistedProxyRanges = mergedRanges;
                    return timing;
                }, TaskManager.INSTANCE.getAsyncExecutor());
    }

    public CompletableFuture<TimingUtil> loadFromFile(Path path, Consumer<IntOpenHashSet> consumer) {
        TimingUtil timing = TimingUtil.startNew();
        return CompletableFuture.supplyAsync(() -> {
            IntOpenHashSet outputSet = new IntOpenHashSet();
            try {
                if (Files.exists(path)) SerializeUtils.deserialize(Files.readAllBytes(path), outputSet);
            } catch (IOException ex) {
                this.logger.log(Level.SEVERE, "Failed to read data from " + path, ex);
            }
            consumer.accept(outputSet);
            return timing;
        }, TaskManager.INSTANCE.getAsyncExecutor());
    }

    private CompletableFuture<Void> loadProxyRangesFromFile() {
        return CompletableFuture.runAsync(() -> {
            if (Files.notExists(this.proxyRangesDataPath)) {
                this.blacklistedProxyRanges = Collections.emptyList();
                return;
            }
            try {
                byte[] bytes = Files.readAllBytes(this.proxyRangesDataPath);
                if (bytes.length % 8 != 0) {
                    this.logger.warning("Ignoring corrupt proxy range cache with invalid length.");
                    this.blacklistedProxyRanges = Collections.emptyList();
                    return;
                }
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                List<GeoRange<Void>> ranges = new ArrayList<>(bytes.length / 8);
                while (buffer.remaining() >= 8) {
                    ranges.add(new GeoRange<>(buffer.getInt(), buffer.getInt(), null));
                }
                this.blacklistedProxyRanges = Collections.unmodifiableList(ranges);
            } catch (IOException ex) {
                this.logger.log(Level.SEVERE, "Failed to read data from " + this.proxyRangesDataPath, ex);
                this.blacklistedProxyRanges = Collections.emptyList();
            }
        }, TaskManager.INSTANCE.getAsyncExecutor());
    }

    public boolean isBlacklistedProxy(int ip) {
        if (this.blacklistedProxies.contains(ip)) return true;

        List<GeoRange<Void>> ranges = this.blacklistedProxyRanges;
        int low = 0;
        int high = ranges.size() - 1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            GeoRange<Void> range = ranges.get(mid);
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
}
