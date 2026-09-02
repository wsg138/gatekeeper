package xyz.lychee.gatekeeper.shared.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;

public class AddressUtils {
    private AddressUtils() throws IllegalAccessException {
        throw new IllegalAccessException();
    }

    public static String fixHostname(String hostname) {
        int zeroIdx = hostname.indexOf(0);
        String cleaned = zeroIdx > -1 ? hostname.substring(0, zeroIdx) : hostname;
        return !cleaned.isEmpty() && cleaned.charAt(cleaned.length() - 1) == '.' ? cleaned.substring(0, cleaned.length() - 1) : cleaned;
    }

    public static boolean isIpv4(InetAddress address) {
        return address != null && address.getAddress().length == 4;
    }

    public static String addressKey(InetAddress address) {
        if (address == null) throw new IllegalArgumentException("Address cannot be null");
        return address.getHostAddress().toLowerCase(Locale.ROOT);
    }

    public static int ipv4ToInt(InetAddress address) {
        if (!isIpv4(address)) {
            throw new IllegalArgumentException("Expected IPv4 address but got " + (address == null ? "null" : address.getHostAddress()));
        }
        return ipv4ToInt(address.getAddress());
    }

    public static int ipv4ToInt(byte[] bytes) {
        if (bytes == null || bytes.length != 4) {
            throw new IllegalArgumentException("Expected exactly 4 bytes for an IPv4 address");
        }
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    public static InetAddress intToIpv4(int address) throws UnknownHostException {
        byte[] bytes = new byte[]{
                (byte) ((address >> 24) & 0xFF),
                (byte) ((address >> 16) & 0xFF),
                (byte) ((address >> 8) & 0xFF),
                (byte) (address & 0xFF)
        };
        return InetAddress.getByAddress(bytes);
    }

    public static int ipv4ToInt(String address) {
        int result = 0;
        int part = 0;
        int len = address.length();

        for (int i = 0; i < len; i++) {
            char c = address.charAt(i);
            if (c == '.') {
                result = (result << 8) | part;
                part = 0;
            } else if (c == ':') {
                break;
            } else {
                part = part * 10 + (c - '0');
            }
        }
        return (result << 8) | part;
    }

    public static boolean isIpv4(String input) {
        if (input == null || input.isEmpty()) return false;

        int len = input.length();
        if (len < 7 || len > 15) return false;

        int value = 0;
        int dots = 0;
        int lastDotIdx = -1;

        for (int i = 0; i < len; i++) {
            char c = input.charAt(i);
            if (c == '.') {
                if (++dots > 3) return false;
                if (i == 0 || input.charAt(i - 1) == '.') return false;
                if (value > 255) return false;
                value = 0;
                lastDotIdx = i;
            } else if (c >= '0' && c <= '9') {
                value = value * 10 + (c - '0');
            } else {
                return false;
            }
        }

        return value < 256 && lastDotIdx != len - 1 && dots == 3;
    }

    /**
     * Returns a stable dotted-decimal representation for a literal IPv4 address,
     * or {@code null} when the input is not a valid IPv4 literal. This deliberately
     * performs no DNS lookup so staff commands cannot accidentally bind hostnames.
     */
    public static String normalizeIpv4(String input) {
        if (!isIpv4(input)) return null;
        int encoded = ipv4ToInt(input);
        return ((encoded >>> 24) & 0xFF) + "."
                + ((encoded >>> 16) & 0xFF) + "."
                + ((encoded >>> 8) & 0xFF) + "."
                + (encoded & 0xFF);
    }

    public static boolean isIpv4Equal(InetAddress address, int addressData) {
        return isIpv4(address) && AddressUtils.ipv4ToInt(address) == addressData;
    }
}
