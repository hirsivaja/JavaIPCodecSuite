package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpPacket;

import java.nio.ByteBuffer;

public record Ipv6Packet(Ipv6Header header, Ipv6Payload payload) implements IpPacket {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        payload.encode(out);
    }

    @Override
    public int length() {
        return header.length() + payload.length();
    }

    public static IpPacket decode(ByteBuffer in) {
        return decode(in, true);
    }

    public static IpPacket decode(ByteBuffer in, boolean ensureChecksum) {
        Ipv6Header header = Ipv6Header.decode(in, ensureChecksum);
        byte[] payloadBytes = new byte[header.payloadOnlyLength()];
        in.get(payloadBytes);
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payloadBytes);
        Ipv6Payload payload = Ipv6Payload.decode(payloadBuffer, ensureChecksum, header);
        return new Ipv6Packet(header, payload);
    }
}
