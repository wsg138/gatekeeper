package xyz.lychee.gatekeeper.shared.objects;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderConditionTest {
    @Test
    void proxyCheckV3TypedDetectionPathsParseCorrectly() {
        JsonConditionSet vpn = JsonConditionSet.compile("detections:vpn=true");
        JsonConditionSet proxy = JsonConditionSet.compile("detections:proxy=true");
        JsonConditionSet tor = JsonConditionSet.compile("detections:tor=true");

        assertNotNull(vpn);
        assertNotNull(proxy);
        assertNotNull(tor);

        String body = "{\"detections\":{\"vpn\":true,\"proxy\":false,\"tor\":false}}";
        assertTrue(vpn.evaluate(body));
        assertFalse(proxy.evaluate(body));
        assertFalse(tor.evaluate(body));
    }
}
