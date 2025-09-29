package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.IpProtocols;
import com.github.hirsivaja.ip.igmp.IgmpPacket;
import com.github.hirsivaja.ip.tcp.TcpPacket;
import com.github.hirsivaja.ip.icmp.IcmpPacket;
import com.github.hirsivaja.ip.udp.UdpPacket;

import java.nio.ByteBuffer;

public sealed interface Ipv4Packet extends IpPacket permits
        IcmpPacket, IgmpPacket, TcpPacket, UdpPacket, EncapsulationPacket,
        EspPacket, AuthenticationPacket, Ipv4Packet.GenericIpv4Packet {
    static IpPacket decode(ByteBuffer in) {
        return decode(in, true);
    }

    static IpPacket decode(ByteBuffer in, boolean ensureChecksum) {
        Ipv4Header header = Ipv4Header.decode(in, ensureChecksum);
        byte[] payload = new byte[header.payloadLength()];
        in.get(payload);
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payload);
        return switch (header.protocol()) {
            case IpProtocols.ICMP -> IcmpPacket.decode(payloadBuffer, header, ensureChecksum);
            case IpProtocols.IGMP -> IgmpPacket.decode(payloadBuffer, header, ensureChecksum);
            case IpProtocols.TCP -> TcpPacket.decode(payloadBuffer, header, ensureChecksum);
            case IpProtocols.UDP -> UdpPacket.decode(payloadBuffer, header, ensureChecksum);
            case IpProtocols.IPV6_ENCAPSULATION -> EncapsulationPacket.decode(payloadBuffer, header);
            case IpProtocols.ESP -> EspPacket.decode(payloadBuffer, header);
            case IpProtocols.AUTHENTICATION -> AuthenticationPacket.decode(payloadBuffer, header);
            default -> GenericIpv4Packet.decode(payloadBuffer, header);
        };
    }

    static boolean isIpv4Packet(ByteBuffer in){
        int currentPosition = in.position();
        boolean isIpv4 = in.remaining() > Ipv4Header.HEADER_LEN && (in.get(0) >>> 4) == Ipv4Header.VERSION;
        in.position(currentPosition);
        return isIpv4;
    }

    record GenericIpv4Packet(Ipv4Header header, ByteArray data) implements Ipv4Packet {

        @Override
        public void encode(ByteBuffer out) {
            header.encode(out);
            out.put(data.array());
        }

        @Override
        public int length() {
            return header.length() + data.array().length;
        }

        public static Ipv4Packet decode(ByteBuffer in, Ipv4Header header) {
            byte[] data = new byte[in.remaining()];
            in.get(data);
            return new GenericIpv4Packet(header, new ByteArray(data));
        }
    }
}
