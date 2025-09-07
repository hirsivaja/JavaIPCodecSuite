package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.igmp.IgmpPayload;
import com.github.hirsivaja.ip.ipsec.EspPayload;
import com.github.hirsivaja.ip.tcp.TcpMessagePayload;
import com.github.hirsivaja.ip.udp.UdpMessagePayload;
import com.github.hirsivaja.ip.icmp.IcmpPayload;

import java.nio.ByteBuffer;

public sealed interface Ipv4Payload extends IpPayload permits
        IcmpPayload, IgmpPayload, TcpMessagePayload, UdpMessagePayload, EncapsulationPayload, EspPayload,
        AuthenticationPayload, Ipv4Payload.GenericIpv4Payload {
    static IpPayload decode(ByteBuffer in) {
        Ipv4Header header = Ipv4Header.decode(in);
        byte[] payload = new byte[header.payloadLength()];
        in.get(payload);
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payload);
        return switch (header.protocol()) {
            case IpProtocol.Type.ICMP -> IcmpPayload.decode(payloadBuffer, header);
            case IpProtocol.Type.IGMP -> IgmpPayload.decode(payloadBuffer, header);
            case IpProtocol.Type.TCP -> TcpMessagePayload.decode(payloadBuffer, header);
            case IpProtocol.Type.UDP -> UdpMessagePayload.decode(payloadBuffer, header);
            case IpProtocol.Type.ENCAPSULATION -> EncapsulationPayload.decode(payloadBuffer, header);
            case IpProtocol.Type.ESP -> EspPayload.decode(payloadBuffer, header);
            case IpProtocol.Type.AUTHENTICATION -> AuthenticationPayload.decode(payloadBuffer, header);
            default -> GenericIpv4Payload.decode(in, header);
        };
    }

    static boolean isIpv4Payload(ByteBuffer in){
        int currentPosition = in.position();
        boolean isIpv4 = in.remaining() > Ipv4Header.HEADER_LEN && (in.get(0) >>> 4) == Ipv4Header.VERSION;
        in.position(currentPosition);
        return isIpv4;
    }

    public record GenericIpv4Payload(Ipv4Header header, ByteArray payload) implements Ipv4Payload {

        @Override
        public void encode(ByteBuffer out) {
            header.encode(out);
            out.put(payload.array());
        }

        @Override
        public int length() {
            return header.length() + payload.array().length;
        }

        public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
            byte[] payload = new byte[in.remaining()];
            in.get(payload);
            return new GenericIpv4Payload(header, new ByteArray(payload));
        }
    }
}
