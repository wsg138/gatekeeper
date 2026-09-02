package xyz.lychee.gatekeeper.shared.modules;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.manager.DataManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;

/**
 * Enforces one-to-one staff-approved VPN endpoint bindings.
 *
 * A matching player/address pair is marked as approved so anonymizer checks can
 * ignore that specific endpoint. The address remains reserved to that player,
 * even if another access-list rule would otherwise whitelist a different user.
 */
public class VpnBindingModule extends AbstractModule {
    public VpnBindingModule(Gatekeeper<?> gatekeeper) {
        super(gatekeeper, "VpnBinding");
    }

    @Override
    public boolean runsForWhitelistedConnections() {
        return true;
    }

    @Override
    public boolean handlePreLogin(GeoConnection connection) {
        DataManager.VpnBindingStatus status = DataManager.INSTANCE.resolveVpnBinding(connection);
        if (status == DataManager.VpnBindingStatus.MATCHED) {
            connection.setApprovedVpnEndpoint(true);
            connection.setDiagnosticAction("ALLOW");
            connection.setDiagnosticReason("vpn_binding");
            connection.setDiagnosticDetail("approved account-specific VPN endpoint matched");
            return false;
        }
        return status == DataManager.VpnBindingStatus.RESERVED_FOR_OTHER;
    }

    @Override
    public String getDecisionCode(GeoConnection connection) {
        return "vpn_endpoint_reserved";
    }

    @Override
    public String getDecisionDetail(GeoConnection connection) {
        return "VPN endpoint is reserved to another account";
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
    public boolean load() {
        return true;
    }

    @Override
    public boolean unload() {
        return true;
    }
}
