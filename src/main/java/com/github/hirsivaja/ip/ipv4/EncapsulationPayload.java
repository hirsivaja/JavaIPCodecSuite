package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;

import java.nio.ByteBuffer;

public record EncapsulationPayload(IpPacket encapsulatedPacket) implements Ipv4Payload {

    @Override
    public void encode(ByteBuffer out) {
        encapsulatedPacket.encode(out);
    }

    @Override
    public int length() {
        return encapsulatedPacket.length();
    }

    public static Ipv4Payload decode(ByteBuffer in, boolean ensureChecksum) {
        IpPacket encapsulatedPacket = Ipv6Packet.decode(in, ensureChecksum);
        return new EncapsulationPayload(encapsulatedPacket);
    }
}
