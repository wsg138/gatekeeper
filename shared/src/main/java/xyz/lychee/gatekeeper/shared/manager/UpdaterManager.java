package xyz.lychee.gatekeeper.shared.manager;

import lombok.Getter;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;

import java.util.Comparator;

/**
 * The Enthusia fork intentionally does not consume upstream GateKeeper update
 * notices. Upstream releases can overwrite or conflict with fork-specific
 * security behavior, so updates are reviewed and merged deliberately instead.
 */
@Getter
public class UpdaterManager extends AbstractManager implements Runnable {
    public static final UpdaterManager INSTANCE = new UpdaterManager();
    private final VersionComparator comparator = new VersionComparator();
    private int compared = 0;
    private int difference = 0;
    private int behind = 0;
    private String latestVersion = "";
    private String currentVersion = "";
    private boolean updater = false;

    @Override
    public boolean load(Gatekeeper<?> plugin) {
        this.currentVersion = plugin.platformData().getPluginVersion().trim();
        this.latestVersion = this.currentVersion;
        this.compared = 0;
        this.difference = 0;
        this.behind = 0;
        this.updater = false;
        return true;
    }

    @Override
    public boolean unload(Gatekeeper<?> plugin) {
        return true;
    }

    @Override
    public boolean reload(Gatekeeper<?> gatekeeper) {
        return true;
    }

    @Override
    public void run() {
        // No-op by design. Fork updates are reviewed and applied manually.
    }

    public static class VersionComparator implements Comparator<String> {
        @Override
        public int compare(String current, String latest) {
            String[] parts1 = current.split("\\.");
            String[] parts2 = latest.split("\\.");

            int length = Math.max(parts1.length, parts2.length);
            for (int i = 0; i < length; i++) {
                int num1 = i < parts1.length ? Integer.parseInt(parts1[i]) : 0;
                int num2 = i < parts2.length ? Integer.parseInt(parts2[i]) : 0;
                if (num1 != num2) return Integer.compare(num1, num2);
            }
            return 0;
        }

        public int difference(String current, String latest) {
            String[] parts1 = current.split("\\.");
            String[] parts2 = latest.split("\\.");

            int length = Math.max(parts1.length, parts2.length);
            for (int i = 0; i < length; i++) {
                int num1 = i < parts1.length ? Integer.parseInt(parts1[i]) : 0;
                int num2 = i < parts2.length ? Integer.parseInt(parts2[i]) : 0;
                if (num1 < num2) return i;
            }
            return -1;
        }
    }
}
