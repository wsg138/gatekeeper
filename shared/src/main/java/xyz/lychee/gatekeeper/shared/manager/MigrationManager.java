package xyz.lychee.gatekeeper.shared.manager;

import dev.dejvokep.boostedyaml.YamlDocument;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.List;

/** One-time fork migration for upstream configuration/cache semantics that were unsafe here. */
public class MigrationManager extends AbstractManager {
    public static final MigrationManager INSTANCE = new MigrationManager();
    public static final String MARKER = ".enthusia-security-v2";
    private static final String TOR_EXIT_SOURCE = "https://check.torproject.org/torbulkexitlist";
    private static final List<String> RESET_MODULES = List.of(
            "AntiVpn.yml",
            "AsnFilter.yml",
            "IpFilter.yml",
            "RateLimit.yml",
            "AccountLimit.yml"
    );

    @Override
    public boolean load(Gatekeeper<?> plugin) throws IOException {
        Path folder = plugin.dataFolder().toPath();
        Files.createDirectories(folder);
        Path marker = folder.resolve(MARKER);
        if (Files.exists(marker)) return true;

        this.backupConfig(folder, plugin);
        this.sanitizeGlobalConfig();

        boolean complete = true;
        complete &= deleteSafely(folder.resolve("proxy_data.bin"), plugin);
        complete &= deleteSafely(folder.resolve("proxy_ranges_data.bin"), plugin);
        complete &= deleteSafely(folder.resolve("asn_data.bin"), plugin);

        Path modules = folder.resolve("modules");
        for (String module : RESET_MODULES) {
            Path file = modules.resolve(module);
            if (!Files.exists(file)) continue;

            Path backup = modules.resolve(module + ".pre-enthusia-v2.bak");
            try {
                if (Files.notExists(backup)) {
                    Files.copy(file, backup, StandardCopyOption.COPY_ATTRIBUTES);
                }
            } catch (IOException ex) {
                plugin.logger().warning("Could not back up legacy module config " + file.getFileName() + ": " + ex.getMessage());
            }
            complete &= deleteSafely(file, plugin);
        }

        if (complete) {
            Files.writeString(marker, "GateKeeper Enthusia security v2 migration complete.\n");
            plugin.logger().info(" &8• &rApplied safe GateKeeper fork defaults and cleared legacy network caches.");
        } else {
            plugin.logger().warning("GateKeeper migration was incomplete; legacy network caches will not be trusted.");
        }
        return true;
    }

    private void backupConfig(Path folder, Gatekeeper<?> plugin) {
        Path config = folder.resolve("config.yml");
        Path backup = folder.resolve("config.yml.pre-enthusia-v2.bak");
        try {
            if (Files.exists(config) && Files.notExists(backup)) {
                Files.copy(config, backup, StandardCopyOption.COPY_ATTRIBUTES);
            }
        } catch (IOException ex) {
            plugin.logger().warning("Could not back up legacy GateKeeper config: " + ex.getMessage());
        }
    }

    private void sanitizeGlobalConfig() throws IOException {
        YamlDocument yaml = ConfigManager.INSTANCE.getYaml();
        yaml.set("main.auto_updater.asn_sources", Collections.emptyList());
        yaml.set("main.auto_updater.proxy_sources", Collections.singletonList(TOR_EXIT_SOURCE));
        yaml.set("main.updater", false);
        yaml.save();
    }

    private static boolean deleteSafely(Path path, Gatekeeper<?> plugin) {
        try {
            Files.deleteIfExists(path);
            return true;
        } catch (IOException ex) {
            plugin.logger().warning("Could not remove legacy GateKeeper cache/config " + path.getFileName() + ": " + ex.getMessage());
            return false;
        }
    }

    @Override
    public boolean unload(Gatekeeper<?> plugin) { return true; }

    @Override
    public boolean reload(Gatekeeper<?> plugin) { return true; }
}
