package xyz.lychee.gatekeeper.shared.modules;

import org.junit.jupiter.api.Test;
import xyz.lychee.gatekeeper.shared.security.RiskSignalType;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReputationModuleTest {
    @Test
    void approvedVpnEndpointSuppressesOnlyExpectedVpnNetworkNoise() {
        assertTrue(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_VPN_IP));
        assertTrue(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_PROXY_IP));
        assertTrue(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_HOSTING_IP));
        assertTrue(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_VPN_ASN));
        assertTrue(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_HOSTING_ASN));

        assertFalse(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_SCANNER_IP));
        assertFalse(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_ABUSE_IP));
        assertFalse(ReputationModule.isVpnEndpointNoise(RiskSignalType.REPUTATION_SCANNER_ASN));
        assertFalse(ReputationModule.isVpnEndpointNoise(RiskSignalType.RAPID_CONNECTIONS));
        assertFalse(ReputationModule.isVpnEndpointNoise(RiskSignalType.ACCOUNT_VELOCITY));
    }
}
