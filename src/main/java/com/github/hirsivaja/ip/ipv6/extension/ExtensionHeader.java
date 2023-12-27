package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public interface ExtensionHeader {
    static ExtensionHeader decode(ByteBuffer in, IpProtocol nextHeader) {
        switch (nextHeader) {
            case HOP_BY_HOP: return HopByHopExtension.decode(in);
            case ROUTING: return RoutingExtension.decode(in);
            case FRAGMENTATION: return FragmentationExtension.decode(in);
            case DESTINATION: return DestinationOptionsExtension.decode(in);
            default: throw new IllegalArgumentException("Unexpected extension header type " + nextHeader);
        }
    }

    IpProtocol getNextHeader();

    void encode(ByteBuffer out);

    int getLength();
}
