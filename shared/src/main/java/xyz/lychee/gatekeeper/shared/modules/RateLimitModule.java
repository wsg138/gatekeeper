package xyz.lychee.gatekeeper.shared.modules;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.manager.TaskManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.security.RiskSignal;
import xyz.lychee.gatekeeper.shared.security.RiskSignalType;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class RateLimitModule extends AbstractModule implements Runnable {
    private final Map<Integer, AttemptWindow> ipAttempts = new ConcurrentHashMap<>();
    private final Deque<Long> serverAttempts = new ArrayDeque<>();

    private ScheduledFuture<?> task;
    private long windowMillis;
    private long burstMillis;
    private int riskAttemptsPerIp;
    private int hardAttemptsPerIp;
    private int hardBurstPerIp;
    private int hardServerAttempts;
    private int riskPoints;

    public RateLimitModule(Gatekeeper<?> gatekeeper) {
        super(gatekeeper, "RateLimit");
    }

    @Override
    public boolean handlePreLogin(GeoConnection connection) {
        if (connection.isLocalhost()) return false;

        long now = connection.getTimestamp() > 0 ? connection.getTimestamp() : System.currentTimeMillis();
        AttemptWindow window = this.ipAttempts.computeIfAbsent(connection.getAddressData(), ignored -> new AttemptWindow());
        AttemptStats stats = window.record(now, this.windowMillis, this.burstMillis);
        int serverCount = this.recordServerAttempt(now);

        if (this.riskAttemptsPerIp > 0 && stats.windowCount >= this.riskAttemptsPerIp) {
            connection.getRiskAssessment().add(new RiskSignal(
                    RiskSignalType.RAPID_CONNECTIONS,
                    this.riskPoints,
                    stats.windowCount + " attempts in " + (this.windowMillis / 1000L) + "s"
            ));
        }

        boolean hardIpLimit = this.hardAttemptsPerIp > 0 && stats.windowCount >= this.hardAttemptsPerIp;
        boolean hardBurstLimit = this.hardBurstPerIp > 0 && stats.burstCount >= this.hardBurstPerIp;
        boolean hardServerLimit = this.hardServerAttempts > 0 && serverCount >= this.hardServerAttempts;
        return hardIpLimit || hardBurstLimit || hardServerLimit;
    }

    private int recordServerAttempt(long now) {
        synchronized (this.serverAttempts) {
            prune(this.serverAttempts, now - this.windowMillis);
            this.serverAttempts.addLast(now);
            return this.serverAttempts.size();
        }
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
    public void run() {
        long cutoff = System.currentTimeMillis() - this.windowMillis;
        this.ipAttempts.entrySet().removeIf(entry -> entry.getValue().isIdle(cutoff));
        synchronized (this.serverAttempts) {
            prune(this.serverAttempts, cutoff);
        }
    }

    @Override
    public boolean load() {
        this.windowMillis = secondsToMillis(positiveOrDefault(this.getConfig().getInt("window_seconds"), 10));
        this.burstMillis = secondsToMillis(positiveOrDefault(this.getConfig().getInt("burst_seconds"), 2));
        this.riskAttemptsPerIp = positiveOrDefault(this.getConfig().getInt("risk_attempts_per_ip"), 5);
        this.hardAttemptsPerIp = positiveOrDefault(this.getConfig().getInt("hard_attempts_per_ip"), 12);
        this.hardBurstPerIp = positiveOrDefault(this.getConfig().getInt("hard_burst_per_ip"), 6);
        this.hardServerAttempts = positiveOrDefault(this.getConfig().getInt("hard_server_attempts"), 200);
        this.riskPoints = positiveOrDefault(
                this.getConfig().getInt("risk_points"),
                RiskSignalType.RAPID_CONNECTIONS.getDefaultPoints()
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
        this.ipAttempts.clear();
        synchronized (this.serverAttempts) {
            this.serverAttempts.clear();
        }
        return true;
    }

    private static int positiveOrDefault(int value, int defaultValue) {
        return value > 0 ? value : defaultValue;
    }

    private static long secondsToMillis(int seconds) {
        return seconds * 1000L;
    }

    private static void prune(Deque<Long> timestamps, long cutoff) {
        while (!timestamps.isEmpty() && timestamps.peekFirst() < cutoff) {
            timestamps.removeFirst();
        }
    }

    private static final class AttemptWindow {
        private final Deque<Long> timestamps = new ArrayDeque<>();

        private synchronized AttemptStats record(long now, long windowMillis, long burstMillis) {
            prune(this.timestamps, now - windowMillis);
            this.timestamps.addLast(now);

            int burstCount = 0;
            Iterator<Long> iterator = this.timestamps.descendingIterator();
            long burstCutoff = now - burstMillis;
            while (iterator.hasNext()) {
                if (iterator.next() < burstCutoff) break;
                burstCount++;
            }
            return new AttemptStats(this.timestamps.size(), burstCount);
        }

        private synchronized boolean isIdle(long cutoff) {
            prune(this.timestamps, cutoff);
            return this.timestamps.isEmpty();
        }
    }

    private static final class AttemptStats {
        private final int windowCount;
        private final int burstCount;

        private AttemptStats(int windowCount, int burstCount) {
            this.windowCount = windowCount;
            this.burstCount = burstCount;
        }
    }
}
