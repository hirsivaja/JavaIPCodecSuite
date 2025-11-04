package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPacket;

import java.nio.ByteBuffer;

public record Ipv4Packet(Ipv4Header header, Ipv4Payload payload) implements IpPacket {

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
        Ipv4Header header = Ipv4Header.decode(in, ensureChecksum);
        byte[] payloadBytes = new byte[header.payloadLength()];
        in.get(payloadBytes);
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payloadBytes);
        Ipv4Payload payload = Ipv4Payload.decode(payloadBuffer, ensureChecksum, header);
        return new Ipv4Packet(header, payload);
    }
}
