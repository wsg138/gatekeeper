package xyz.lychee.gatekeeper.shared.manager;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.security.SecuritySnapshot;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Short-lived staff diagnostics for recent connection decisions.
 * Data is intentionally memory-only and expires automatically.
 */
public class SecurityHistoryManager extends AbstractManager {
    public static final SecurityHistoryManager INSTANCE = new SecurityHistoryManager();

    private static final long TTL_MILLIS = 30L * 60L * 1000L;
    private static final int MAX_ENTRIES = 2000;

    private final Map<String, SecuritySnapshot> byName = new ConcurrentHashMap<>();
    private final Map<String, SecuritySnapshot> byAddress = new ConcurrentHashMap<>();

    @Override
    public boolean load(Gatekeeper<?> plugin) {
        return true;
    }

    @Override
    public boolean unload(Gatekeeper<?> plugin) {
        this.byName.clear();
        this.byAddress.clear();
        return true;
    }

    @Override
    public boolean reload(Gatekeeper<?> plugin) {
        this.prune();
        return true;
    }

    public void record(GeoConnection connection, String action, String reason, String detail) {
        if (connection == null) return;

        long now = System.currentTimeMillis();
        SecuritySnapshot snapshot = new SecuritySnapshot(
                connection.getName(),
                connection.getAddress().getHostAddress(),
                connection.getAsn(),
                connection.getCountry(),
                action,
                reason,
                detail,
                connection.getRiskAssessment().getScore(),
                connection.getRiskAssessment().getSignals(),
                now
        );

        this.byName.put(connection.getName().toLowerCase(Locale.ROOT), snapshot);
        this.byAddress.put(snapshot.getAddress(), snapshot);

        if (this.byName.size() > MAX_ENTRIES || this.byAddress.size() > MAX_ENTRIES) {
            this.prune();
            this.trimOldest();
        }
    }

    public SecuritySnapshot find(String target) {
        if (target == null || target.isBlank()) return null;
        this.prune();

        SecuritySnapshot byIp = this.byAddress.get(target.trim());
        if (byIp != null) return byIp;
        return this.byName.get(target.trim().toLowerCase(Locale.ROOT));
    }

    private void prune() {
        long cutoff = System.currentTimeMillis() - TTL_MILLIS;
        this.byName.entrySet().removeIf(entry -> entry.getValue().getCreatedAtMillis() < cutoff);
        this.byAddress.entrySet().removeIf(entry -> entry.getValue().getCreatedAtMillis() < cutoff);
    }

    private void trimOldest() {
        while (this.byName.size() > MAX_ENTRIES) {
            String oldestKey = null;
            long oldest = Long.MAX_VALUE;
            for (Map.Entry<String, SecuritySnapshot> entry : this.byName.entrySet()) {
                if (entry.getValue().getCreatedAtMillis() < oldest) {
                    oldest = entry.getValue().getCreatedAtMillis();
                    oldestKey = entry.getKey();
                }
            }
            if (oldestKey == null) break;
            SecuritySnapshot removed = this.byName.remove(oldestKey);
            if (removed != null) this.byAddress.remove(removed.getAddress(), removed);
        }

        while (this.byAddress.size() > MAX_ENTRIES) {
            String oldestKey = null;
            long oldest = Long.MAX_VALUE;
            for (Map.Entry<String, SecuritySnapshot> entry : this.byAddress.entrySet()) {
                if (entry.getValue().getCreatedAtMillis() < oldest) {
                    oldest = entry.getValue().getCreatedAtMillis();
                    oldestKey = entry.getKey();
                }
            }
            if (oldestKey == null) break;
            SecuritySnapshot removed = this.byAddress.remove(oldestKey);
            if (removed != null) this.byName.remove(removed.getName().toLowerCase(Locale.ROOT), removed);
        }
    }
}
