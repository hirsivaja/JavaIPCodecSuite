package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpPacket;

import java.nio.ByteBuffer;

public record EncapsulationPayload(IpPacket encapsulatedPacket) implements Ipv6Payload {

    @Override
    public void encode(ByteBuffer out) {
        encapsulatedPacket.encode(out);
    }

    @Override
    public int length() {
        return encapsulatedPacket.length();
    }

    public static Ipv6Payload decode(ByteBuffer in, boolean ensureChecksum) {
        IpPacket encapsulatedPacket = Ipv6Packet.decode(in, ensureChecksum);
        return new EncapsulationPayload(encapsulatedPacket);
    }
}
