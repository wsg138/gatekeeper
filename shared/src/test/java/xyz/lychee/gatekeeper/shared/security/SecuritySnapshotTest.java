package xyz.lychee.gatekeeper.shared.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

final class SecuritySnapshotTest {
    @Test
    void constructorDefensivelyCopiesSignalsAndExposesImmutableView() {
        var source = new ArrayList<RiskSignal>();
        source.add(new RiskSignal(RiskSignalType.REPUTATION_VPN_IP, 20, "vpn"));

        var snapshot = new SecuritySnapshot(
                "Player",
                "203.0.113.10",
                64500,
                "US",
                "DENY",
                "risk",
                null,
                20,
                source,
                1234L);

        source.clear();

        assertEquals(1, snapshot.getSignals().size());
        assertThrows(UnsupportedOperationException.class,
                () -> snapshot.getSignals().add(new RiskSignal(RiskSignalType.RAPID_CONNECTIONS, 60, "burst")));
        assertEquals("", snapshot.getDetail());
    }

    @Test
    void snapshotPreservesAuditFieldsExactly() {
        List<RiskSignal> signals = List.of(new RiskSignal(RiskSignalType.ACCOUNT_VELOCITY, 50, "many accounts"));
        var snapshot = new SecuritySnapshot(
                "Alice",
                "198.51.100.7",
                13335,
                "CA",
                "CHALLENGE",
                "velocity",
                "manual review",
                50,
                signals,
                987654321L);

        assertEquals("Alice", snapshot.getName());
        assertEquals("198.51.100.7", snapshot.getAddress());
        assertEquals(13335, snapshot.getAsn());
        assertEquals("CA", snapshot.getCountry());
        assertEquals("CHALLENGE", snapshot.getAction());
        assertEquals("velocity", snapshot.getReason());
        assertEquals("manual review", snapshot.getDetail());
        assertEquals(50, snapshot.getScore());
        assertEquals(987654321L, snapshot.getCreatedAtMillis());
        assertEquals(signals, snapshot.getSignals());
    }
}
