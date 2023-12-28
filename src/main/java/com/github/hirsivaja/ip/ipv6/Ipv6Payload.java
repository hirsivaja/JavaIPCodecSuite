package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.tcp.TcpMessagePayload;
import com.github.hirsivaja.ip.udp.UdpMessagePayload;

import java.nio.ByteBuffer;

public interface Ipv6Payload extends IpPayload {
    int NEXT_HEADER_INDEX = 6;

    static boolean isExtension(IpProtocol nextHeader) {
        return nextHeader == IpProtocol.ROUTING ||
                nextHeader == IpProtocol.HOP_BY_HOP ||
                nextHeader == IpProtocol.FRAGMENTATION ||
                nextHeader == IpProtocol.DESTINATION;
    }

    static IpPayload decode(ByteBuffer in) {
        Ipv6Header header = Ipv6Header.decode(in);
        switch (header.getLastNextHeader()) {
            case TCP: return TcpMessagePayload.decode(in, header);
            case UDP: return UdpMessagePayload.decode(in, header);
            case ICMPV6: return Icmpv6Payload.decode(in, header);
            case ENCAPSULATION: return EncapsulationPayload.decode(in, header);
            default: throw new IllegalArgumentException("Unexpected command payload type " + header.getNextHeader());
        }
    }

    static boolean isIpv6Payload(ByteBuffer in) {
        int currentPosition = in.position();
        if(in.remaining() >= Ipv6Header.HEADER_LEN && (in.get(0) >>> 4) == Ipv6Header.VERSION) {
            IpProtocol nextHeader = IpProtocol.getType(in.get(NEXT_HEADER_INDEX));
            in.position(currentPosition);
            return nextHeader == IpProtocol.ICMPV6 ||
                    nextHeader == IpProtocol.UDP ||
                    nextHeader == IpProtocol.ENCAPSULATION ||
                    nextHeader == IpProtocol.ROUTING ||
                    nextHeader == IpProtocol.FRAGMENTATION ||
                    nextHeader == IpProtocol.HOP_BY_HOP ||
                    nextHeader == IpProtocol.DESTINATION;
        }
        in.position(currentPosition);
        return false;
    }
}
