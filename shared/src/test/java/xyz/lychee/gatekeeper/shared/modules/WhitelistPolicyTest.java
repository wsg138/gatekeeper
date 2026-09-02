package xyz.lychee.gatekeeper.shared.modules;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WhitelistPolicyTest {
    @Test
    void whitelistStillRunsAvailabilityAndVpnReservationProtection() {
        assertTrue(new RateLimitModule(null).runsForWhitelistedConnections());
        assertTrue(new VpnBindingModule(null).runsForWhitelistedConnections());
        assertFalse(new AntiVpnModule(null).runsForWhitelistedConnections());
        assertFalse(new AccountLimitModule(null).runsForWhitelistedConnections());
        assertFalse(new IpFilterModule(null).runsForWhitelistedConnections());
        assertFalse(new ReputationModule(null).runsForWhitelistedConnections());
    }
}
