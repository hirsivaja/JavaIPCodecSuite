package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.IpProtocols;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.ipsec.EspPayload;
import com.github.hirsivaja.ip.tcp.TcpMessagePayload;
import com.github.hirsivaja.ip.udp.UdpMessagePayload;

import java.nio.ByteBuffer;

public sealed interface Ipv6Payload extends IpPayload permits
        TcpMessagePayload, UdpMessagePayload, EspPayload, Icmpv6Payload, EncapsulationPayload,
        Ipv6Payload.GenericIpv6Payload {
    int NEXT_HEADER_INDEX = 6;

    static IpPayload decode(ByteBuffer in) {
        Ipv6Header header = Ipv6Header.decode(in);
        byte[] ipv6Payload = new byte[header.payloadOnlyLength()];
        in.get(ipv6Payload);
        ByteBuffer payloadBuffer = ByteBuffer.wrap(ipv6Payload);
        return switch (header.lastNextHeader()) {
            case IpProtocols.TCP -> TcpMessagePayload.decode(payloadBuffer, header);
            case IpProtocols.UDP -> UdpMessagePayload.decode(payloadBuffer, header);
            case IpProtocols.ESP -> EspPayload.decode(payloadBuffer, header);
            case IpProtocols.ICMPV6 -> Icmpv6Payload.decode(payloadBuffer, header);
            case IpProtocols.IPV6_ENCAPSULATION -> EncapsulationPayload.decode(payloadBuffer, header);
            default -> GenericIpv6Payload.decode(in, header);
        };
    }

    static boolean isIpv6Payload(ByteBuffer in) {
        int currentPosition = in.position();
        if(in.remaining() >= Ipv6Header.HEADER_LEN && (in.get(0) >>> 4) == Ipv6Header.VERSION) {
            IpProtocol nextHeader = IpProtocol.fromType(in.get(NEXT_HEADER_INDEX));
            in.position(currentPosition);
            return nextHeader == IpProtocols.ICMPV6 ||
                    nextHeader == IpProtocols.UDP ||
                    nextHeader == IpProtocols.IPV6_ENCAPSULATION ||
                    nextHeader == IpProtocols.IPV6_ROUTING ||
                    nextHeader == IpProtocols.IPV6_FRAGMENTATION ||
                    nextHeader == IpProtocols.AUTHENTICATION ||
                    nextHeader == IpProtocols.HOP_BY_HOP ||
                    nextHeader == IpProtocols.IPV6_DESTINATION;
        }
        in.position(currentPosition);
        return false;
    }

    record GenericIpv6Payload(Ipv6Header header, ByteArray payload) implements Ipv6Payload {

        @Override
        public void encode(ByteBuffer out) {
            header.encode(out);
            out.put(payload.array());
        }

        @Override
        public int length() {
            return header.length() + payload.array().length;
        }

        public static Ipv6Payload decode(ByteBuffer in, Ipv6Header header) {
            byte[] payload = new byte[in.remaining()];
            in.get(payload);
            return new GenericIpv6Payload(header, new ByteArray(payload));
        }
    }
}
