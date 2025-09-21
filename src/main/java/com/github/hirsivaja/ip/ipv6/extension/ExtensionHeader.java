package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.IpProtocols;
import com.github.hirsivaja.ip.ipsec.EspHeader;

import java.nio.ByteBuffer;

public interface ExtensionHeader {

    static boolean isExtension(IpProtocol nextHeader) {
        return nextHeader == IpProtocols.HOP_BY_HOP ||
                nextHeader == IpProtocols.IPV6_ROUTING ||
                nextHeader == IpProtocols.IPV6_FRAGMENTATION ||
                nextHeader == IpProtocols.ESP ||
                nextHeader == IpProtocols.AUTHENTICATION ||
                nextHeader == IpProtocols.IPV6_DESTINATION ||
                nextHeader == IpProtocols.MOBILITY_HEADER ||
                nextHeader == IpProtocols.HIP ||
                nextHeader == IpProtocols.SHIM6;
    }

    static ExtensionHeader decode(ByteBuffer in, IpProtocol nextHeader) {
        return decode(in, nextHeader, true);
    }

    static ExtensionHeader decode(ByteBuffer in, IpProtocol nextHeader, boolean ensureChecksum) {
        return switch (nextHeader) {
            case IpProtocols.HOP_BY_HOP -> HopByHopExtension.decode(in);
            case IpProtocols.IPV6_ROUTING -> RoutingExtension.decode(in);
            case IpProtocols.IPV6_FRAGMENTATION -> FragmentationExtension.decode(in);
            case IpProtocols.ESP -> EspHeader.decode(in);
            case IpProtocols.AUTHENTICATION -> AuthenticationHeaderExtension.decode(in);
            case IpProtocols.IPV6_DESTINATION -> DestinationOptionsExtension.decode(in);
            case IpProtocols.MOBILITY_HEADER -> MobilityHeaderExtension.decode(in, ensureChecksum);
            case IpProtocols.HIP -> HipExtension.decode(in, ensureChecksum);
            case IpProtocols.SHIM6 -> Shim6Extension.decode(in);
            default -> throw new IllegalArgumentException("Unexpected extension header type " + nextHeader);
        };
    }

    IpProtocol nextHeader();

    void encode(ByteBuffer out);

    int length();
}
