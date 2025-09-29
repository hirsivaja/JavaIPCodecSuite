package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.IpProtocols;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Packet;
import com.github.hirsivaja.ip.tcp.TcpPacket;
import com.github.hirsivaja.ip.udp.UdpPacket;

import java.nio.ByteBuffer;

public sealed interface Ipv6Packet extends IpPacket permits
        TcpPacket, UdpPacket, Icmpv6Packet, EncapsulationPacket,
        Ipv6Packet.GenericIpv6Packet {
    int NEXT_HEADER_INDEX = 6;

    static IpPacket decode(ByteBuffer in) {
        return decode(in, true);
    }

    static IpPacket decode(ByteBuffer in, boolean ensureChecksum) {
        Ipv6Header header = Ipv6Header.decode(in, ensureChecksum);
        byte[] ipv6Payload = new byte[header.payloadOnlyLength()];
        in.get(ipv6Payload);
        ByteBuffer payloadBuffer = ByteBuffer.wrap(ipv6Payload);
        return switch (header.lastNextHeader()) {
            case IpProtocols.TCP -> TcpPacket.decode(payloadBuffer, header, ensureChecksum);
            case IpProtocols.UDP -> UdpPacket.decode(payloadBuffer, header, ensureChecksum);
            case IpProtocols.ICMPV6 -> Icmpv6Packet.decode(payloadBuffer, header, ensureChecksum);
            case IpProtocols.IPV6_ENCAPSULATION -> EncapsulationPacket.decode(payloadBuffer, header);
            default -> GenericIpv6Packet.decode(payloadBuffer, header);
        };
    }

    static boolean isIpv6Packet(ByteBuffer in) {
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

    record GenericIpv6Packet(Ipv6Header header, ByteArray data) implements Ipv6Packet {

        @Override
        public void encode(ByteBuffer out) {
            header.encode(out);
            out.put(data.array());
        }

        @Override
        public int length() {
            return header.length() + data.array().length;
        }

        public static Ipv6Packet decode(ByteBuffer in, Ipv6Header header) {
            byte[] data = new byte[in.remaining()];
            in.get(data);
            return new GenericIpv6Packet(header, new ByteArray(data));
        }
    }
}
