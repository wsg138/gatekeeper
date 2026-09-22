package xyz.lychee.gatekeeper.shared.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

final class RiskSignalTest {
    @Test
    void negativePointsClampToZeroAndNullDetailBecomesEmpty() {
        var signal = new RiskSignal(RiskSignalType.REPUTATION_VPN_IP, -25, null);

        assertEquals(RiskSignalType.REPUTATION_VPN_IP, signal.getType());
        assertEquals(0, signal.getPoints());
        assertEquals("", signal.getDetail());
    }

    @Test
    void positivePointsAndDetailArePreserved() {
        var signal = new RiskSignal(RiskSignalType.RAPID_CONNECTIONS, 73, "burst detected");

        assertEquals(73, signal.getPoints());
        assertEquals("burst detected", signal.getDetail());
    }

    @Test
    void signalTypeMetadataRemainsStableForPolicyConsumers() {
        assertEquals("rapid_connections", RiskSignalType.RAPID_CONNECTIONS.getConfigKey());
        assertEquals(60, RiskSignalType.RAPID_CONNECTIONS.getDefaultPoints());
        assertEquals(RiskStrength.STRONG, RiskSignalType.RAPID_CONNECTIONS.getStrength());

        assertEquals("vpn_ip", RiskSignalType.REPUTATION_VPN_IP.getConfigKey());
        assertEquals(20, RiskSignalType.REPUTATION_VPN_IP.getDefaultPoints());
        assertEquals(RiskStrength.MEDIUM, RiskSignalType.REPUTATION_VPN_IP.getStrength());
    }
}
