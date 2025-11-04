package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.*;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.tcp.TcpSegment;
import com.github.hirsivaja.ip.udp.UdpDatagram;

import java.nio.ByteBuffer;

public sealed interface Ipv6Payload extends IpPayload permits Icmpv6Payload, EncapsulationPayload, Ipv6Payload.Generic, TcpSegment, UdpDatagram {

    static Ipv6Payload decode(ByteBuffer in, boolean ensureChecksum, Ipv6Header header) {
        return switch (header.lastNextHeader()) {
            case IpProtocols.TCP -> TcpSegment.decode(in, ensureChecksum, header);
            case IpProtocols.UDP -> UdpDatagram.decode(in, ensureChecksum, header);
            case IpProtocols.ICMPV6 -> Icmpv6Payload.decode(in, ensureChecksum, header);
            case IpProtocols.IPV6_ENCAPSULATION -> EncapsulationPayload.decode(in, ensureChecksum);
            default -> Ipv6Payload.Generic.decode(in, header.lastNextHeader());
        };
    }

    record Generic(IpProtocol protocol, ByteArray data) implements Ipv6Payload {

        @Override
        public void encode(ByteBuffer out) {
            out.put(data.array());
        }

        @Override
        public int length() {
            return data.array().length;
        }

        public static Ipv6Payload decode(ByteBuffer in, IpProtocol protocol) {
            byte[] data = new byte[in.remaining()];
            in.get(data);
            return new Generic(protocol, new ByteArray(data));
        }
    }
}
