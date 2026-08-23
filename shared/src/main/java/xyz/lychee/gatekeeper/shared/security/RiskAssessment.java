package xyz.lychee.gatekeeper.shared.security;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public final class RiskAssessment {
    private final Map<RiskSignalType, RiskSignal> signals = new EnumMap<>(RiskSignalType.class);

    public synchronized void add(RiskSignal signal) {
        if (signal == null || signal.getPoints() <= 0) return;

        RiskSignal existing = this.signals.get(signal.getType());
        if (existing == null || signal.getPoints() > existing.getPoints()) {
            this.signals.put(signal.getType(), signal);
        }
    }

    public synchronized int getScore() {
        int score = 0;
        for (RiskSignal signal : this.signals.values()) {
            score += signal.getPoints();
        }
        return score;
    }

    public synchronized boolean hasStrongSignal() {
        for (RiskSignal signal : this.signals.values()) {
            if (signal.getType().getStrength() == RiskStrength.STRONG) {
                return true;
            }
        }
        return false;
    }

    public synchronized boolean hasSignal(RiskSignalType type) {
        return this.signals.containsKey(type);
    }

    public synchronized List<RiskSignal> getSignals() {
        return new ArrayList<>(this.signals.values());
    }
}
