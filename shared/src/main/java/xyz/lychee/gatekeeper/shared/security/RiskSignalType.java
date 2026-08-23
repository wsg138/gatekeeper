package xyz.lychee.gatekeeper.shared.security;

public enum RiskSignalType {
    REPUTATION_VPN_IP("vpn_ip", 20, RiskStrength.MEDIUM),
    REPUTATION_PROXY_IP("proxy_ip", 20, RiskStrength.MEDIUM),
    REPUTATION_HOSTING_IP("hosting_ip", 8, RiskStrength.WEAK),
    REPUTATION_SCANNER_IP("scanner_ip", 10, RiskStrength.WEAK),
    REPUTATION_ABUSE_IP("abuse_ip", 8, RiskStrength.WEAK),
    REPUTATION_VPN_ASN("vpn_asn", 15, RiskStrength.MEDIUM),
    REPUTATION_HOSTING_ASN("hosting_asn", 8, RiskStrength.WEAK),
    REPUTATION_SCANNER_ASN("scanner_asn", 5, RiskStrength.WEAK),

    RAPID_CONNECTIONS("rapid_connections", 60, RiskStrength.STRONG),
    ACCOUNT_VELOCITY("account_velocity", 50, RiskStrength.STRONG),
    RECONNECT_BURST("reconnect_burst", 25, RiskStrength.MEDIUM);

    private final String configKey;
    private final int defaultPoints;
    private final RiskStrength strength;

    RiskSignalType(String configKey, int defaultPoints, RiskStrength strength) {
        this.configKey = configKey;
        this.defaultPoints = defaultPoints;
        this.strength = strength;
    }

    public String getConfigKey() {
        return configKey;
    }

    public int getDefaultPoints() {
        return defaultPoints;
    }

    public RiskStrength getStrength() {
        return strength;
    }
}
