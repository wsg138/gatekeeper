package xyz.lychee.gatekeeper.shared;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import org.junit.jupiter.api.Test;

final class FullFeatureCoverageContractTest {
    private static final List<String> REQUIRED_TESTS = List.of(
            "xyz.lychee.gatekeeper.shared.manager.DataManagerPersistenceTest",
            "xyz.lychee.gatekeeper.shared.manager.VpnBindingDataManagerTest",
            "xyz.lychee.gatekeeper.shared.modules.ReputationModuleTest",
            "xyz.lychee.gatekeeper.shared.modules.WhitelistPolicyTest",
            "xyz.lychee.gatekeeper.shared.objects.CommandPlayerPrivacyTest",
            "xyz.lychee.gatekeeper.shared.objects.ConditionSetTest",
            "xyz.lychee.gatekeeper.shared.objects.ProviderConditionTest",
            "xyz.lychee.gatekeeper.shared.security.AnonymizerConsensusTest",
            "xyz.lychee.gatekeeper.shared.security.RiskAssessmentTest",
            "xyz.lychee.gatekeeper.shared.security.RiskPolicyTest",
            "xyz.lychee.gatekeeper.shared.security.RiskSignalTest",
            "xyz.lychee.gatekeeper.shared.security.SecuritySnapshotTest",
            "xyz.lychee.gatekeeper.shared.util.AddressUtilsTest",
            "xyz.lychee.gatekeeper.shared.util.MathUtilsTest");

    @Test
    void maintainedSharedCoreRegressionSuitesRemainPresent() {
        for (String className : REQUIRED_TESTS) {
            assertDoesNotThrow(
                    () -> Class.forName(className),
                    () -> "Required Gatekeeper regression suite is missing: " + className);
        }
    }
}
