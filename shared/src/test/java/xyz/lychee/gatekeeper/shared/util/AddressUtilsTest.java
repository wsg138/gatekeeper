package xyz.lychee.gatekeeper.shared.util;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AddressUtilsTest {
    @Test
    void ipv6AddressesNeverCollapseIntoFakeIpv4Keys() throws Exception {
        InetAddress first = InetAddress.getByName("2001:db8::1");
        InetAddress second = InetAddress.getByName("2001:db8::2");

        assertFalse(AddressUtils.isIpv4(first));
        assertFalse(AddressUtils.isIpv4(second));
        assertNotEquals(AddressUtils.addressKey(first), AddressUtils.addressKey(second));
        assertThrows(IllegalArgumentException.class, () -> AddressUtils.ipv4ToInt(first));
    }

    @Test
    void ipv4ConversionRemainsStable() throws Exception {
        InetAddress address = InetAddress.getByName("203.0.113.42");
        assertTrue(AddressUtils.isIpv4(address));
        int encoded = AddressUtils.ipv4ToInt(address);
        assertTrue(AddressUtils.isIpv4Equal(address, encoded));
    }
}
