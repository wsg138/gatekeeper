package xyz.lychee.gatekeeper.shared.security;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnonymizerConsensusTest {
    @Test
    void requiresIndependentProviderConsensus() {
        AnonymizerConsensus.Decision decision = AnonymizerConsensus.decide(
                Arrays.asList(
                        EnumSet.of(AnonymizerType.VPN),
                        Collections.emptySet(),
                        Collections.emptySet()
                ),
                2
        );

        assertFalse(decision.isBlocked());
        assertNull(decision.getReason());
        assertEquals(1, decision.getPositiveProviders());
    }

    @Test
    void givesSpecificReasonOnlyWhenSpecificTypeAlsoReachesConsensus() {
        AnonymizerConsensus.Decision vpn = AnonymizerConsensus.decide(
                Arrays.asList(
                        EnumSet.of(AnonymizerType.VPN),
                        EnumSet.of(AnonymizerType.VPN, AnonymizerType.PROXY),
                        Collections.emptySet()
                ),
                2
        );

        assertTrue(vpn.isBlocked());
        assertEquals(AnonymizerType.VPN, vpn.getReason());

        AnonymizerConsensus.Decision mixed = AnonymizerConsensus.decide(
                Arrays.asList(
                        EnumSet.of(AnonymizerType.VPN),
                        EnumSet.of(AnonymizerType.PROXY),
                        Collections.emptySet()
                ),
                2
        );

        assertTrue(mixed.isBlocked());
        assertEquals(AnonymizerType.ANONYMIZER, mixed.getReason());
    }

    @Test
    void torReasonRequiresTorConsensus() {
        AnonymizerConsensus.Decision decision = AnonymizerConsensus.decide(
                Arrays.asList(
                        EnumSet.of(AnonymizerType.TOR),
                        EnumSet.of(AnonymizerType.TOR),
                        EnumSet.of(AnonymizerType.PROXY)
                ),
                2
        );

        assertTrue(decision.isBlocked());
        assertEquals(AnonymizerType.TOR, decision.getReason());
    }
}
