package xyz.lychee.gatekeeper.shared.security;

public enum AnonymizerType {
    VPN("vpn"),
    PROXY("proxy"),
    TOR("tor"),
    ANONYMIZER("anonymizer");

    private final String configKey;

    AnonymizerType(String configKey) {
        this.configKey = configKey;
    }

    public String getConfigKey() {
        return this.configKey;
    }

    public static AnonymizerType fromConfigKey(String key) {
        if (key == null) return null;
        for (AnonymizerType type : values()) {
            if (type.configKey.equalsIgnoreCase(key.trim())) {
                return type;
            }
        }
        return null;
    }
}
