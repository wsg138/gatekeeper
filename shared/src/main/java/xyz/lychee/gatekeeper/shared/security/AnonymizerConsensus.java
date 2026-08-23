package xyz.lychee.gatekeeper.shared.security;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AnonymizerConsensus {
    private AnonymizerConsensus() {}

    public static Decision decide(List<Set<AnonymizerType>> providerSignals, int blockThreshold) {
        int threshold = Math.max(1, blockThreshold);
        int positiveProviders = 0;
        Map<AnonymizerType, Integer> typeVotes = new EnumMap<>(AnonymizerType.class);

        for (Set<AnonymizerType> signals : providerSignals) {
            if (signals == null || signals.isEmpty()) continue;

            positiveProviders++;
            for (AnonymizerType type : signals) {
                if (type == null || type == AnonymizerType.ANONYMIZER) continue;
                typeVotes.merge(type, 1, Integer::sum);
            }
        }

        if (positiveProviders < threshold) {
            return new Decision(false, null, positiveProviders);
        }

        // Only show a specific player-facing reason when that exact reason itself
        // reached consensus. Otherwise use a generic anonymizer message instead of guessing.
        AnonymizerType reason = findConsensusReason(typeVotes, threshold);
        if (reason == null) reason = AnonymizerType.ANONYMIZER;

        return new Decision(true, reason, positiveProviders);
    }

    private static AnonymizerType findConsensusReason(Map<AnonymizerType, Integer> votes, int threshold) {
        // Tor is the most specific classification, followed by VPN and proxy.
        AnonymizerType[] order = {
                AnonymizerType.TOR,
                AnonymizerType.VPN,
                AnonymizerType.PROXY
        };

        for (AnonymizerType type : order) {
            if (votes.getOrDefault(type, 0) >= threshold) {
                return type;
            }
        }
        return null;
    }

    public static final class Decision {
        private final boolean blocked;
        private final AnonymizerType reason;
        private final int positiveProviders;

        public Decision(boolean blocked, AnonymizerType reason, int positiveProviders) {
            this.blocked = blocked;
            this.reason = reason;
            this.positiveProviders = positiveProviders;
        }

        public boolean isBlocked() {
            return blocked;
        }

        public AnonymizerType getReason() {
            return reason;
        }

        public int getPositiveProviders() {
            return positiveProviders;
        }
    }
}
