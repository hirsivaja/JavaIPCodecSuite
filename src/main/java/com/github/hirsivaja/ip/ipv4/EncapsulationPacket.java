package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;

import java.nio.ByteBuffer;

public record EncapsulationPacket(Ipv4Header header, IpPacket encapsulatedPacket) implements Ipv4Packet {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        encapsulatedPacket.encode(out);
    }

    @Override
    public int length() {
        return header.length() + encapsulatedPacket.length();
    }

    public static Ipv4Packet decode(ByteBuffer in, Ipv4Header header) {
        IpPacket encapsulatedPacket = Ipv6Packet.decode(in);
        return new EncapsulationPacket(header, encapsulatedPacket);
    }
}
