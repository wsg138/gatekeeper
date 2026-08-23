package xyz.lychee.gatekeeper.shared.modules;

import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.security.RiskAssessment;
import xyz.lychee.gatekeeper.shared.security.RiskPolicy;
import xyz.lychee.gatekeeper.shared.security.RiskSignal;
import xyz.lychee.gatekeeper.shared.security.RiskSignalType;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public class RiskModule extends AbstractModule {
    private boolean enforce;
    private boolean requireStrongSignal;
    private int blockScore;
    private int logScore;
    private Object rapidKickMessage;
    private Object accountKickMessage;
    private Object combinedKickMessage;

    public RiskModule(Gatekeeper<?> gatekeeper) {
        super(gatekeeper, "Risk");
    }

    @Override
    public boolean handlePreLogin(GeoConnection connection) {
        RiskAssessment assessment = connection.getRiskAssessment();
        int score = assessment.getScore();
        boolean wouldBlock = RiskPolicy.shouldBlock(assessment, this.blockScore, this.requireStrongSignal);

        if (score >= this.logScore || wouldBlock) {
            String action = wouldBlock ? (this.enforce ? "BLOCK" : "SHADOW_BLOCK") : "ALLOW";
            this.getGatekeeper().logger().info(
                    "Connection risk for " + connection.getAddress().getHostAddress() + "/" + connection.getName()
                            + ": score=" + score
                            + ", action=" + action
                            + ", signals=[" + describe(assessment.getSignals()) + "]"
            );
        }

        return this.enforce && wouldBlock;
    }

    @Override
    public Object getKickMessage(GeoConnection connection) {
        if (connection == null) return super.getKickMessage(null);

        RiskAssessment assessment = connection.getRiskAssessment();
        boolean rapid = assessment.hasSignal(RiskSignalType.RAPID_CONNECTIONS);
        boolean accounts = assessment.hasSignal(RiskSignalType.ACCOUNT_VELOCITY);

        if (rapid && accounts) return this.combinedKickMessage;
        if (accounts) return this.accountKickMessage;
        if (rapid) return this.rapidKickMessage;
        return super.getKickMessage(connection);
    }

    @Override
    public String getDecisionCode(GeoConnection connection) {
        if (connection == null) return "risk";
        RiskAssessment assessment = connection.getRiskAssessment();
        boolean rapid = assessment.hasSignal(RiskSignalType.RAPID_CONNECTIONS);
        boolean accounts = assessment.hasSignal(RiskSignalType.ACCOUNT_VELOCITY);
        if (rapid && accounts) return "automated_behavior";
        if (accounts) return "account_velocity";
        if (rapid) return "rapid_connections";
        return "risk";
    }

    @Override
    public String getDecisionDetail(GeoConnection connection) {
        if (connection == null) return "";
        return "score=" + connection.getRiskAssessment().getScore()
                + "; " + describe(connection.getRiskAssessment().getSignals());
    }

    @Override
    public boolean handlePostLogin(GeoConnection connection) { return false; }

    @Override
    public boolean handleDisconnect(GeoConnection connection) { return false; }

    @Override
    public boolean load() {
        String mode = this.getConfig().getString("mode");
        if (mode == null || mode.isBlank()) mode = "enforce";
        this.enforce = !"shadow".equalsIgnoreCase(mode.trim());
        this.blockScore = positiveOrDefault(this.getConfig().getInt("block_score"), 90);
        this.logScore = Math.max(0, this.getConfig().getInt("log_score"));
        this.requireStrongSignal = this.getConfig().getBoolean("require_strong_signal");

        Object fallback = super.getKickMessage(null);
        this.rapidKickMessage = this.loadMessage("kick_reasons.rapid_connections", fallback);
        this.accountKickMessage = this.loadMessage("kick_reasons.account_velocity", fallback);
        this.combinedKickMessage = this.loadMessage("kick_reasons.automated_behavior", fallback);
        return true;
    }

    @Override
    public boolean unload() { return true; }

    private static String describe(List<RiskSignal> signals) {
        if (signals.isEmpty()) return "none";
        return signals.stream()
                .map(signal -> signal.getType().getConfigKey().toLowerCase(Locale.ROOT)
                        + ":+" + signal.getPoints()
                        + (signal.getDetail().isEmpty() ? "" : "(" + signal.getDetail() + ")"))
                .collect(Collectors.joining(", "));
    }

    private static int positiveOrDefault(int value, int defaultValue) {
        return value > 0 ? value : defaultValue;
    }
}
