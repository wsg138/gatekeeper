package xyz.lychee.gatekeeper.shared.objects;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConditionSetTest {
    @Test
    void jsonAndRequiresEveryTermWhilePipeRemainsOr() {
        JsonConditionSet condition = JsonConditionSet.compile("vpn=true&proxy=true|tor=true");
        assertNotNull(condition);

        assertFalse(condition.evaluate("{\"vpn\":true,\"proxy\":false,\"tor\":false}"));
        assertTrue(condition.evaluate("{\"vpn\":true,\"proxy\":true,\"tor\":false}"));
        assertTrue(condition.evaluate("{\"vpn\":false,\"proxy\":false,\"tor\":true}"));
    }

    @Test
    void textAndRequiresEveryTermWhilePipeRemainsOr() {
        TextConditionSet condition = TextConditionSet.compile("contains=foo&contains=bar|equals=baz");
        assertNotNull(condition);

        assertFalse(condition.evaluate("foo only"));
        assertTrue(condition.evaluate("foo and bar"));
        assertTrue(condition.evaluate("BAZ"));
    }
}
