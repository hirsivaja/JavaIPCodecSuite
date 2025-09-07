package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public interface ExtensionHeader {
    static ExtensionHeader decode(ByteBuffer in, IpProtocol nextHeader) {
        return switch (nextHeader) {
            case IpProtocol.Type.HOP_BY_HOP -> HopByHopExtension.decode(in);
            case IpProtocol.Type.ROUTING -> RoutingExtension.decode(in);
            case IpProtocol.Type.FRAGMENTATION -> FragmentationExtension.decode(in);
            case IpProtocol.Type.AUTHENTICATION -> AuthenticationHeaderExtension.decode(in);
            case IpProtocol.Type.DESTINATION -> DestinationOptionsExtension.decode(in);
            default -> throw new IllegalArgumentException("Unexpected extension header type " + nextHeader);
        };
    }

    IpProtocol nextHeader();

    void encode(ByteBuffer out);

    int length();
}
