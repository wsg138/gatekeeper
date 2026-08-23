package xyz.lychee.gatekeeper.shared.modules;

import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.manager.GeoipManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;

import java.io.IOException;

public class IpFilterModule extends AbstractModule {
    private final IntOpenHashSet listedIps = new IntOpenHashSet();
    private boolean listMode;
    private Object torKickMessage;

    public IpFilterModule(Gatekeeper<?> gatekeeper) {
        super(gatekeeper, "IpFilter");
    }

    @Override
    public boolean handlePreLogin(GeoConnection connection) {
        if (connection.isLocalhost() || !connection.isIpv4()) return false;

        if (GeoipManager.INSTANCE.isBlacklistedProxy(connection.getAddressData())) {
            return true;
        }

        return this.listedIps.contains(connection.getAddressData()) == this.listMode;
    }

    @Override
    public Object getKickMessage(GeoConnection connection) {
        if (connection != null && connection.isIpv4()
                && GeoipManager.INSTANCE.isBlacklistedProxy(connection.getAddressData())) {
            return this.torKickMessage;
        }
        return super.getKickMessage(connection);
    }

    @Override
    public String getDecisionCode(GeoConnection connection) {
        if (connection != null && connection.isIpv4()
                && GeoipManager.INSTANCE.isBlacklistedProxy(connection.getAddressData())) {
            return "tor";
        }
        return "manual_ip_block";
    }

    @Override
    public String getDecisionDetail(GeoConnection connection) {
        if (connection != null && connection.isIpv4()
                && GeoipManager.INSTANCE.isBlacklistedProxy(connection.getAddressData())) {
            return "official Tor exit list";
        }
        return "staff-managed IPv4 filter";
    }

    @Override
    public boolean handlePostLogin(GeoConnection connection) { return false; }

    @Override
    public boolean handleDisconnect(GeoConnection connection) { return false; }

    @Override
    public boolean load() throws IOException {
        this.listedIps.clear();

        for (String address : this.getConfig().getStringList("list")) {
            if (AddressUtils.isIpv4(address)) {
                this.listedIps.add(AddressUtils.ipv4ToInt(address));
            }
        }
        this.listMode = this.getConfig().getBoolean("list_mode");
        this.torKickMessage = this.loadMessage("kick_reasons.tor", super.getKickMessage(null));
        return true;
    }

    @Override
    public boolean unload() {
        this.listedIps.clear();
        this.torKickMessage = null;
        return true;
    }
}
