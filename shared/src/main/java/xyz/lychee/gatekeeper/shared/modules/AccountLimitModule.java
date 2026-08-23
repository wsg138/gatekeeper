package xyz.lychee.gatekeeper.shared.modules;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.manager.TaskManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.security.RiskSignal;
import xyz.lychee.gatekeeper.shared.security.RiskSignalType;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class AccountLimitModule extends AbstractModule implements Runnable {
    private final Map<String, AtomicInteger> connectedByIp = new ConcurrentHashMap<>();
    private final Map<String, AccountWindow> recentAccounts = new ConcurrentHashMap<>();

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
        AccountWindow window = this.recentAccounts.computeIfAbsent(connection.getAddressKey(), ignored -> new AccountWindow());
        int uniqueAccounts = window.record(connection.getName(), now, this.velocityWindowMillis);

        if (this.riskUniqueAccounts > 0 && uniqueAccounts >= this.riskUniqueAccounts) {
            connection.getRiskAssessment().add(new RiskSignal(
                    RiskSignalType.ACCOUNT_VELOCITY,
                    this.riskPoints,
                    uniqueAccounts + " unique accounts in " + (this.velocityWindowMillis / 60_000L) + "m"
            ));
        }

        if (this.accountLimitPerIp <= 0) return false;
        AtomicInteger connected = this.connectedByIp.get(connection.getAddressKey());
        return connected != null && connected.get() >= this.accountLimitPerIp;
    }

    @Override
    public String getDecisionDetail(GeoConnection connection) {
        return "simultaneous account emergency ceiling exceeded";
    }

    @Override
    public boolean handlePostLogin(GeoConnection connection) {
        if (!connection.isLocalhost()) {
            this.connectedByIp.computeIfAbsent(connection.getAddressKey(), ignored -> new AtomicInteger())
                    .incrementAndGet();
        }
        return false;
    }

    @Override
    public boolean handleDisconnect(GeoConnection connection) {
        if (!connection.isLocalhost()) {
            this.connectedByIp.computeIfPresent(connection.getAddressKey(), (ignored, count) ->
                    count.decrementAndGet() > 0 ? count : null
            );
        }
        return false;
    }

    @Override
    public void run() {
        long cutoff = System.currentTimeMillis() - this.velocityWindowMillis;
        this.recentAccounts.entrySet().removeIf(entry -> entry.getValue().isEmptyAfter(cutoff));
    }

    @Override
    public boolean load() {
        boolean modernConfig = this.getConfig().contains("velocity_window_minutes");
        // Upstream's legacy default was a hard limit of 3. If that file survives
        // migration, never inherit that false-positive-prone value.
        this.accountLimitPerIp = modernConfig
                ? Math.max(0, this.getConfig().getInt("per_ip_limit"))
                : 20;
        this.velocityWindowMillis = minutesToMillis(
                modernConfig ? positiveOrDefault(this.getConfig().getInt("velocity_window_minutes"), 10) : 10
        );
        this.riskUniqueAccounts = modernConfig
                ? Math.max(0, this.getConfig().getInt("risk_unique_accounts"))
                : 10;
        this.riskPoints = modernConfig
                ? positiveOrDefault(this.getConfig().getInt("risk_points"), RiskSignalType.ACCOUNT_VELOCITY.getDefaultPoints())
                : RiskSignalType.ACCOUNT_VELOCITY.getDefaultPoints();

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

    private static int positiveOrDefault(int value, int defaultValue) { return value > 0 ? value : defaultValue; }
    private static long minutesToMillis(int minutes) { return minutes * 60_000L; }

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
