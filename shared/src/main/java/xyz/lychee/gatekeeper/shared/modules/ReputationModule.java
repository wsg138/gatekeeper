package xyz.lychee.gatekeeper.shared.modules;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.manager.ReputationManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.security.RiskSignal;
import xyz.lychee.gatekeeper.shared.security.RiskSignalType;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;

/**
 * Converts broad network reputation into risk context only. This module never
 * rejects a player by itself.
 */
public class ReputationModule extends AbstractModule {
    private static final RiskSignalType[] TYPES = {
            RiskSignalType.REPUTATION_VPN_IP,
            RiskSignalType.REPUTATION_PROXY_IP,
            RiskSignalType.REPUTATION_HOSTING_IP,
            RiskSignalType.REPUTATION_SCANNER_IP,
            RiskSignalType.REPUTATION_ABUSE_IP,
            RiskSignalType.REPUTATION_VPN_ASN,
            RiskSignalType.REPUTATION_HOSTING_ASN,
            RiskSignalType.REPUTATION_SCANNER_ASN
    };

    private final Map<RiskSignalType, Integer> scores = new EnumMap<>(RiskSignalType.class);

    public ReputationModule(Gatekeeper<?> gatekeeper) {
        super(gatekeeper, "Reputation");
    }

    @Override
    public boolean handlePreLogin(GeoConnection connection) {
        if (connection.isLocalhost() || !connection.isIpv4()) return false;

        EnumSet<RiskSignalType> matches = ReputationManager.INSTANCE.assess(
                connection.getAddressData(),
                connection.getAsn()
        );

        for (RiskSignalType type : matches) {
            int points = this.scores.getOrDefault(type, type.getDefaultPoints());
            if (points <= 0) continue;
            connection.getRiskAssessment().add(new RiskSignal(type, points, "network reputation"));
        }

        return false;
    }

    @Override
    public boolean handlePostLogin(GeoConnection connection) { return false; }

    @Override
    public boolean handleDisconnect(GeoConnection connection) { return false; }

    @Override
    public boolean load() {
        this.scores.clear();
        for (RiskSignalType type : TYPES) {
            String path = "scores." + type.getConfigKey();
            int points = this.getConfig().contains(path)
                    ? this.getConfig().getInt(path)
                    : type.getDefaultPoints();
            this.scores.put(type, Math.max(0, points));
        }
        return true;
    }

    @Override
    public boolean unload() {
        this.scores.clear();
        return true;
    }
}
