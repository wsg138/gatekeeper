package xyz.lychee.gatekeeper.shared.objects;

import xyz.lychee.gatekeeper.shared.manager.DataManager;
import xyz.lychee.gatekeeper.shared.manager.ModuleManager;
import xyz.lychee.gatekeeper.shared.manager.SecurityHistoryManager;
import xyz.lychee.gatekeeper.shared.util.TimingUtil;

import java.net.InetAddress;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.Lock;

public class ListenerHandler {
    private static final LongAdder CHECKS = new LongAdder();
    private static final LongAdder DETECTIONS = new LongAdder();

    public void handleDisconnect(InetAddress address, String name) {
        GeoConnection connection = new GeoConnection(address, name);
        Lock lock = ModuleManager.INSTANCE.readLock();
        lock.lock();
        try {
            for (AbstractModule module : ModuleManager.INSTANCE.getLoadedChecks()) {
                module.handleDisconnect(connection);
            }
        } finally {
            lock.unlock();
        }
    }

    public void handlePostLogin(InetAddress address, String name) {
        GeoConnection connection = new GeoConnection(address, name);
        Lock lock = ModuleManager.INSTANCE.readLock();
        lock.lock();
        try {
            for (AbstractModule module : ModuleManager.INSTANCE.getLoadedChecks()) {
                module.handlePostLogin(connection);
            }
        } finally {
            lock.unlock();
        }
    }

    public Object handlePreLogin(InetAddress address, String name) {
        TimingUtil timer = TimingUtil.startNew();
        GeoConnection connection = new GeoConnection(address, name);
        connection.setTimestamp(System.currentTimeMillis());
        CHECKS.increment();

        boolean whitelisted = DataManager.INSTANCE.updateAndCheckAccess(connection, EnumAccess.WHITELIST);

        Lock lock = ModuleManager.INSTANCE.readLock();
        lock.lock();
        try {
            for (AbstractModule module : ModuleManager.INSTANCE.getLoadedChecks()) {
                if (whitelisted && !module.runsForWhitelistedConnections()) continue;

                if (module.handlePreLogin(connection)) {
                    DETECTIONS.increment();
                    module.printCheck(connection, timer);
                    SecurityHistoryManager.INSTANCE.record(
                            connection,
                            "BLOCK",
                            module.getDecisionCode(connection),
                            module.getDecisionDetail(connection)
                    );
                    return module.getKickMessage(connection);
                }
            }
        } finally {
            lock.unlock();
        }

        if (connection.getDiagnosticAction() != null) {
            SecurityHistoryManager.INSTANCE.record(
                    connection,
                    connection.getDiagnosticAction(),
                    connection.getDiagnosticReason() == null ? "risk" : connection.getDiagnosticReason(),
                    connection.getDiagnosticDetail() == null ? "" : connection.getDiagnosticDetail()
            );
        } else {
            SecurityHistoryManager.INSTANCE.record(
                    connection,
                    "ALLOW",
                    whitelisted ? "whitelist" : "clean",
                    whitelisted ? "staff whitelist bypass; flood protection remained active" : ""
            );
        }
        return null;
    }

    public static long getChecks() {
        long checks = CHECKS.longValue();
        CHECKS.reset();
        return checks;
    }

    public static long getDetections() {
        long detections = DETECTIONS.longValue();
        DETECTIONS.reset();
        return detections;
    }
}
