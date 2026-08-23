package xyz.lychee.gatekeeper.shared.manager;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** One-time fork migration for downloaded caches that had different semantics upstream. */
public class MigrationManager extends AbstractManager {
    public static final MigrationManager INSTANCE = new MigrationManager();
    private static final String MARKER = ".enthusia-security-v1";

    @Override
    public boolean load(Gatekeeper<?> plugin) throws IOException {
        Path folder = plugin.dataFolder().toPath();
        Files.createDirectories(folder);
        Path marker = folder.resolve(MARKER);
        if (Files.exists(marker)) return true;

        // These are downloaded/rebuildable caches only. data.json (staff access
        // lists) and geodata.ldb are deliberately preserved.
        Files.deleteIfExists(folder.resolve("proxy_data.bin"));
        Files.deleteIfExists(folder.resolve("proxy_ranges_data.bin"));
        Files.deleteIfExists(folder.resolve("asn_data.bin"));
        Files.writeString(marker, "GateKeeper Enthusia security cache migration complete.\n");

        plugin.logger().info(" &8• &rCleared legacy GateKeeper network-intelligence caches for the fork.");
        return true;
    }

    @Override
    public boolean unload(Gatekeeper<?> plugin) { return true; }

    @Override
    public boolean reload(Gatekeeper<?> plugin) { return true; }
}
