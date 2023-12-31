package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.igmp.IgmpPayload;
import com.github.hirsivaja.ip.tcp.TcpMessagePayload;
import com.github.hirsivaja.ip.udp.UdpMessagePayload;
import com.github.hirsivaja.ip.icmp.IcmpPayload;

import java.nio.ByteBuffer;

public interface Ipv4Payload extends IpPayload {
    static IpPayload decode(ByteBuffer in) {
        Ipv4Header header = Ipv4Header.decode(in);
        switch (header.getProtocol()) {
            case ICMP: return IcmpPayload.decode(in, header);
            case IGMP: return IgmpPayload.decode(in, header);
            case TCP: return TcpMessagePayload.decode(in, header);
            case UDP: return UdpMessagePayload.decode(in, header);
            case ENCAPSULATION: return EncapsulationPayload.decode(in, header);
            default: throw new IllegalArgumentException("Unexpected command payload type " + header.getProtocol());
        }
    }

    static boolean isIpv4Payload(ByteBuffer in){
        int currentPosition = in.position();
        boolean isIpv4 = in.remaining() > Ipv4Header.HEADER_LEN && (in.get(0) >>> 4) == Ipv4Header.VERSION;
        in.position(currentPosition);
        return isIpv4;
    }
}
