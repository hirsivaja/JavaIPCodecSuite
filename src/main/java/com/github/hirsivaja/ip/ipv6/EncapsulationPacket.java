package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpPacket;

import java.nio.ByteBuffer;

public record EncapsulationPacket(Ipv6Header header, IpPacket encapsulatedPacket) implements Ipv6Packet {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        encapsulatedPacket.encode(out);
    }

    @Override
    public int length() {
        return header.length() + encapsulatedPacket.length();
    }

    public static IpPacket decode(ByteBuffer in, Ipv6Header header) {
        IpPacket encapsulatedPacket = Ipv6Packet.decode(in);
        return new EncapsulationPacket(header, encapsulatedPacket);
    }
}
