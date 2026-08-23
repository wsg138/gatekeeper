package xyz.lychee.gatekeeper.shared.modules;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.manager.TaskManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.security.RiskSignal;
import xyz.lychee.gatekeeper.shared.security.RiskSignalType;

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class AccountLimitModule extends AbstractModule implements Runnable {
    private final Map<Integer, AtomicInteger> connectedByIp = new ConcurrentHashMap<>();
    private final Map<Integer, AccountWindow> recentAccounts = new ConcurrentHashMap<>();

    private ScheduledFuture<?> task;
    private int accountLimitPerIp;
    private long velocityWindowMillis;
    private int riskUniqueAccounts;
    private int riskPoints;

    public AccountLimitModule(Gatekeeper<?> gatekeeper) {
        super(gatekeeper, "AccountLimit");
    }

    @Override
    public boolean handlePreLogin(GeoConnection connection) {
        if (connection.isLocalhost()) return false;

        long now = connection.getTimestamp() > 0 ? connection.getTimestamp() : System.currentTimeMillis();
        AccountWindow window = this.recentAccounts.computeIfAbsent(
                connection.getAddressData(),
                ignored -> new AccountWindow()
        );
        int uniqueAccounts = window.record(connection.getName(), now, this.velocityWindowMillis);

        if (this.riskUniqueAccounts > 0 && uniqueAccounts >= this.riskUniqueAccounts) {
            connection.getRiskAssessment().add(new RiskSignal(
                    RiskSignalType.ACCOUNT_VELOCITY,
                    this.riskPoints,
                    uniqueAccounts + " unique accounts in " + (this.velocityWindowMillis / 60_000L) + "m"
            ));
        }

        // The simultaneous-account limit is deliberately a high emergency ceiling.
        // Shared households, dorms and CGNAT can legitimately put many players on
        // one public IP, so ordinary suspicious activity is handled by risk scoring.
        if (this.accountLimitPerIp <= 0) return false;
        AtomicInteger connected = this.connectedByIp.get(connection.getAddressData());
        return connected != null && connected.get() >= this.accountLimitPerIp;
    }

    @Override
    public boolean handlePostLogin(GeoConnection connection) {
        if (!connection.isLocalhost()) {
            this.connectedByIp.computeIfAbsent(connection.getAddressData(), ignored -> new AtomicInteger())
                    .incrementAndGet();
        }
        return false;
    }

    @Override
    public boolean handleDisconnect(GeoConnection connection) {
        if (!connection.isLocalhost()) {
            this.connectedByIp.computeIfPresent(connection.getAddressData(), (ignored, count) -> {
                return count.decrementAndGet() > 0 ? count : null;
            });
        }
        return false;
    }

    @Override
    public void run() {
        long cutoff = System.currentTimeMillis() - this.velocityWindowMillis;
        Iterator<Map.Entry<Integer, AccountWindow>> iterator = this.recentAccounts.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<Integer, AccountWindow> entry = iterator.next();
            if (entry.getValue().isEmptyAfter(cutoff)) {
                this.recentAccounts.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    @Override
    public boolean load() {
        // Zero intentionally disables the hard simultaneous-account cap. Negative
        // values are also treated as disabled rather than silently becoming strict.
        this.accountLimitPerIp = Math.max(0, this.getConfig().getInt("per_ip_limit"));
        this.velocityWindowMillis = minutesToMillis(
                positiveOrDefault(this.getConfig().getInt("velocity_window_minutes"), 10)
        );
        this.riskUniqueAccounts = positiveOrDefault(this.getConfig().getInt("risk_unique_accounts"), 6);
        this.riskPoints = positiveOrDefault(
                this.getConfig().getInt("risk_points"),
                RiskSignalType.ACCOUNT_VELOCITY.getDefaultPoints()
        );

        this.task = TaskManager.INSTANCE.getScheduler().scheduleAtFixedRate(this, 1, 1, TimeUnit.MINUTES);
        return true;
    }

    @Override
    public boolean unload() {
        if (this.task != null) {
            this.task.cancel(false);
            this.task = null;
        }
        this.connectedByIp.clear();
        this.recentAccounts.clear();
        return true;
    }

    private static int positiveOrDefault(int value, int defaultValue) {
        return value > 0 ? value : defaultValue;
    }

    private static long minutesToMillis(int minutes) {
        return minutes * 60_000L;
    }

    private static final class AccountWindow {
        private final Map<String, Long> lastSeen = new ConcurrentHashMap<>();

        private int record(String name, long now, long windowMillis) {
            long cutoff = now - windowMillis;
            this.lastSeen.entrySet().removeIf(entry -> entry.getValue() < cutoff);
            this.lastSeen.put(name.toLowerCase(Locale.ROOT), now);
            return this.lastSeen.size();
        }

        private boolean isEmptyAfter(long cutoff) {
            this.lastSeen.entrySet().removeIf(entry -> entry.getValue() < cutoff);
            return this.lastSeen.isEmpty();
        }
    }
}
