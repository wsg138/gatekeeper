package xyz.lychee.gatekeeper.shared.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class MathUtilsTest {
    @Test
    void integerRecognitionAcceptsSignedWholeNumbersOnly() {
        assertTrue(MathUtils.isInteger("0"));
        assertTrue(MathUtils.isInteger("42"));
        assertTrue(MathUtils.isInteger("-42"));
        assertFalse(MathUtils.isInteger(null));
        assertFalse(MathUtils.isInteger(""));
        assertFalse(MathUtils.isInteger(" 42"));
        assertFalse(MathUtils.isInteger("+42"));
        assertFalse(MathUtils.isInteger("4.2"));
        assertFalse(MathUtils.isInteger("--1"));
    }

    @Test
    void roundingUsesRequestedDecimalPrecision() {
        assertEquals(12.35, MathUtils.round(12.345, 2), 0.000001);
        assertEquals(-12.35, MathUtils.round(-12.345, 2), 0.000001);
        assertEquals(13.0, MathUtils.round(12.6, 0), 0.000001);
        assertEquals(1.235, MathUtils.round(1.2346, 3), 0.000001);
    }
}
