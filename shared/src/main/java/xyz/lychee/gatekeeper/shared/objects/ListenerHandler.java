package xyz.lychee.gatekeeper.shared.objects;

import xyz.lychee.gatekeeper.shared.manager.DataManager;
import xyz.lychee.gatekeeper.shared.manager.ModuleManager;
import xyz.lychee.gatekeeper.shared.manager.SecurityHistoryManager;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;
import xyz.lychee.gatekeeper.shared.util.TimingUtil;

import java.net.InetAddress;
import java.util.concurrent.atomic.LongAdder;

public class ListenerHandler {
    private static final LongAdder CHECKS = new LongAdder();
    private static final LongAdder DETECTIONS = new LongAdder();

    public void handleDisconnect(InetAddress address, String name) {
        int addressData = AddressUtils.ipv4ToInt(address);
        GeoConnection connection = new GeoConnection(address, addressData, name);
        for (AbstractModule module : ModuleManager.INSTANCE.getLoadedChecks()) {
            module.handleDisconnect(connection);
        }
    }

    public void handlePostLogin(InetAddress address, String name) {
        int addressData = AddressUtils.ipv4ToInt(address);
        GeoConnection connection = new GeoConnection(address, addressData, name);
        for (AbstractModule module : ModuleManager.INSTANCE.getLoadedChecks()) {
            module.handlePostLogin(connection);
        }
    }

    public Object handlePreLogin(InetAddress address, String name) {
        TimingUtil timer = TimingUtil.startNew();

        int addressData = AddressUtils.ipv4ToInt(address);
        GeoConnection connection = new GeoConnection(address, addressData, name);
        connection.setTimestamp(System.currentTimeMillis());
        CHECKS.increment();

        if (DataManager.INSTANCE.updateAndCheckAccess(connection, EnumAccess.WHITELIST)) {
            SecurityHistoryManager.INSTANCE.record(connection, "ALLOW", "whitelist", "staff whitelist bypass");
            return null;
        }

        for (AbstractModule module : ModuleManager.INSTANCE.getLoadedChecks()) {
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

        SecurityHistoryManager.INSTANCE.record(connection, "ALLOW", "clean", "");
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
