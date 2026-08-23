package xyz.lychee.gatekeeper.shared.objects;

import lombok.Getter;
import lombok.Setter;
import xyz.lychee.gatekeeper.shared.manager.GeoipManager;
import xyz.lychee.gatekeeper.shared.security.RiskAssessment;

import java.net.InetAddress;

@Getter
@Setter
public class GeoConnection {
    private final InetAddress address;
    private final String name;
    private final int addressData;
    private final boolean localhost;
    private final String country;
    private final int asn;
    private final RiskAssessment riskAssessment = new RiskAssessment();
    private volatile long timestamp = -1L;
    private volatile EnumAccess access = EnumAccess.NULL;

    public GeoConnection(InetAddress address, int addressData, String name) {
        this.address = address;
        this.name = name;
        this.addressData = addressData;
        this.localhost = address.isLoopbackAddress();

        BinaryGeoIPDatabase database = GeoipManager.INSTANCE.getDatabase();
        this.country = database.getCountryCode(this.addressData);
        this.asn = database.getAsnCode(this.addressData);
    }
}
