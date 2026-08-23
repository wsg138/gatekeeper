package xyz.lychee.gatekeeper.shared.security;

public final class RiskPolicy {
    private RiskPolicy() {}

    public static boolean shouldBlock(RiskAssessment assessment, int blockScore, boolean requireStrongSignal) {
        if (assessment == null) return false;
        if (assessment.getScore() < Math.max(1, blockScore)) return false;
        return !requireStrongSignal || assessment.hasStrongSignal();
    }
}
