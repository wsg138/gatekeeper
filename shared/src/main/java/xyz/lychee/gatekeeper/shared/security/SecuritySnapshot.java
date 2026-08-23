package xyz.lychee.gatekeeper.shared.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class SecuritySnapshot {
    private final String name;
    private final String address;
    private final int asn;
    private final String country;
    private final String action;
    private final String reason;
    private final String detail;
    private final int score;
    private final List<RiskSignal> signals;
    private final long createdAtMillis;

    public SecuritySnapshot(
            String name,
            String address,
            int asn,
            String country,
            String action,
            String reason,
            String detail,
            int score,
            List<RiskSignal> signals,
            long createdAtMillis
    ) {
        this.name = name;
        this.address = address;
        this.asn = asn;
        this.country = country;
        this.action = action;
        this.reason = reason;
        this.detail = detail == null ? "" : detail;
        this.score = score;
        this.signals = Collections.unmodifiableList(new ArrayList<>(signals));
        this.createdAtMillis = createdAtMillis;
    }

    public String getName() { return name; }
    public String getAddress() { return address; }
    public int getAsn() { return asn; }
    public String getCountry() { return country; }
    public String getAction() { return action; }
    public String getReason() { return reason; }
    public String getDetail() { return detail; }
    public int getScore() { return score; }
    public List<RiskSignal> getSignals() { return signals; }
    public long getCreatedAtMillis() { return createdAtMillis; }
}
