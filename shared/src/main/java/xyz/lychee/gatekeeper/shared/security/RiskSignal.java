package xyz.lychee.gatekeeper.shared.security;

public final class RiskSignal {
    private final RiskSignalType type;
    private final int points;
    private final String detail;

    public RiskSignal(RiskSignalType type, int points, String detail) {
        this.type = type;
        this.points = Math.max(0, points);
        this.detail = detail == null ? "" : detail;
    }

    public RiskSignalType getType() {
        return type;
    }

    public int getPoints() {
        return points;
    }

    public String getDetail() {
        return detail;
    }
}
