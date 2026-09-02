package xyz.lychee.gatekeeper.shared.objects;

import lombok.Getter;
import lombok.Setter;
import xyz.lychee.gatekeeper.shared.manager.GeoipManager;
import xyz.lychee.gatekeeper.shared.security.RiskAssessment;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;

import java.net.InetAddress;

@Getter
@Setter
public class GeoConnection {
    private final InetAddress address;
    private final String name;
    private final String addressKey;
    private final int addressData;
    private final boolean ipv4;
    private final boolean localhost;
    private final String country;
    private final int asn;
    private final RiskAssessment riskAssessment = new RiskAssessment();
    private volatile long timestamp = -1L;
    private volatile EnumAccess access = EnumAccess.NULL;
    private volatile boolean approvedVpnEndpoint;
    private volatile String diagnosticAction;
    private volatile String diagnosticReason;
    private volatile String diagnosticDetail;

    public GeoConnection(InetAddress address, String name) {
        this.address = address;
        this.name = name;
        this.addressKey = AddressUtils.addressKey(address);
        this.ipv4 = AddressUtils.isIpv4(address);
        this.addressData = this.ipv4 ? AddressUtils.ipv4ToInt(address) : 0;
        this.localhost = address.isLoopbackAddress();

        if (this.ipv4) {
            BinaryGeoIPDatabase database = GeoipManager.INSTANCE.getDatabase();
            this.country = database.getCountryCode(this.addressData);
            this.asn = database.getAsnCode(this.addressData);
        } else {
            this.country = BinaryGeoIPDatabase.UNKNOWN_COUNTRY;
            this.asn = 0;
        }
    }

    public GeoConnection(InetAddress address, int ignoredAddressData, String name) {
        this(address, name);
    }
}
