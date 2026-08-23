package xyz.lychee.gatekeeper.shared.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskPolicyTest {
    @Test
    void reputationOnlyCannotBlockWhenStrongSignalIsRequired() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_VPN_IP, 40, "vpn-list"));
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_PROXY_IP, 40, "proxy-list"));
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_SCANNER_IP, 20, "scanner-list"));

        assertFalse(RiskPolicy.shouldBlock(assessment, 90, true));
    }

    @Test
    void strongBehaviorPlusEnoughContextCanBlock() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.add(new RiskSignal(RiskSignalType.RAPID_CONNECTIONS, 60, "rapid"));
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_PROXY_IP, 20, "proxy"));
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_SCANNER_IP, 10, "scanner"));

        assertTrue(RiskPolicy.shouldBlock(assessment, 90, true));
    }

    @Test
    void strongSignalStillNeedsThreshold() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.add(new RiskSignal(RiskSignalType.ACCOUNT_VELOCITY, 50, "accounts"));

        assertFalse(RiskPolicy.shouldBlock(assessment, 90, true));
    }
}
