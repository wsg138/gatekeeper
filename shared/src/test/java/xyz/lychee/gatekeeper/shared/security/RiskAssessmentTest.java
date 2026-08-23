package xyz.lychee.gatekeeper.shared.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskAssessmentTest {
    @Test
    void duplicateReputationCategoryDoesNotStack() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_ABUSE_IP, 8, "feed-a"));
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_ABUSE_IP, 8, "feed-b"));

        assertEquals(8, assessment.getScore());
        assertEquals(1, assessment.getSignals().size());
        assertFalse(assessment.hasStrongSignal());
    }

    @Test
    void strongerReplacementWinsWithinSameCategory() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_PROXY_IP, 10, "old"));
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_PROXY_IP, 20, "new"));

        assertEquals(20, assessment.getScore());
    }

    @Test
    void behavioralSignalMarksAssessmentStrong() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.add(new RiskSignal(RiskSignalType.REPUTATION_HOSTING_IP, 8, "hosting"));
        assessment.add(new RiskSignal(RiskSignalType.RAPID_CONNECTIONS, 60, "burst"));

        assertEquals(68, assessment.getScore());
        assertTrue(assessment.hasStrongSignal());
    }
}
