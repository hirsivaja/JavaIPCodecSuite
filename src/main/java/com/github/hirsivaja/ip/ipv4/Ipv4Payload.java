package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.*;
import com.github.hirsivaja.ip.icmp.IcmpPayload;
import com.github.hirsivaja.ip.igmp.IgmpPayload;
import com.github.hirsivaja.ip.tcp.TcpSegment;
import com.github.hirsivaja.ip.udp.UdpDatagram;

import java.nio.ByteBuffer;

public sealed interface Ipv4Payload extends IpPayload permits IcmpPayload, IgmpPayload, AuthenticationPayload, EncapsulationPayload, EspPayload, Ipv4Payload.Generic, TcpSegment, UdpDatagram {

    static Ipv4Payload decode(ByteBuffer in, boolean ensureChecksum, Ipv4Header header) {
        return switch (header.protocol()) {
            case IpProtocols.ICMP -> IcmpPayload.decode(in, ensureChecksum);
            case IpProtocols.IGMP -> IgmpPayload.decode(in);
            case IpProtocols.TCP -> TcpSegment.decode(in, ensureChecksum, header);
            case IpProtocols.UDP -> UdpDatagram.decode(in, ensureChecksum, header);
            case IpProtocols.IPV6_ENCAPSULATION -> EncapsulationPayload.decode(in, ensureChecksum);
            case IpProtocols.ESP -> EspPayload.decode(in);
            case IpProtocols.AUTHENTICATION -> AuthenticationPayload.decode(in, ensureChecksum);
            default -> Ipv4Payload.Generic.decode(in, header.protocol());
        };
    }

    record Generic(IpProtocol protocol, ByteArray data) implements Ipv4Payload {

        @Override
        public void encode(ByteBuffer out) {
            out.put(data.array());
        }

        @Override
        public int length() {
            return data.array().length;
        }

        public static Ipv4Payload decode(ByteBuffer in, IpProtocol protocol) {
            byte[] data = new byte[in.remaining()];
            in.get(data);
            return new Generic(protocol, new ByteArray(data));
        }
    }
}
