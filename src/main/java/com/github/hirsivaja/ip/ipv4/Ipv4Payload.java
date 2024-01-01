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
        byte[] payload = new byte[header.getDataLength() - Ipv4Header.HEADER_LEN];
        in.get(payload);
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payload);
        switch (header.getProtocol()) {
            case ICMP: return IcmpPayload.decode(payloadBuffer, header);
            case IGMP: return IgmpPayload.decode(payloadBuffer, header);
            case TCP: return TcpMessagePayload.decode(payloadBuffer, header);
            case UDP: return UdpMessagePayload.decode(payloadBuffer, header);
            case ENCAPSULATION: return EncapsulationPayload.decode(payloadBuffer, header);
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
