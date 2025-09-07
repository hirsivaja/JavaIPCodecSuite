package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpPayload;

import java.nio.ByteBuffer;

public record EncapsulationPayload(Ipv6Header header, IpPayload encapsulatedPayload) implements Ipv6Payload {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        encapsulatedPayload.encode(out);
    }

    @Override
    public int length() {
        return header.length() + encapsulatedPayload.length();
    }

    public static IpPayload decode(ByteBuffer in, Ipv6Header header) {
        IpPayload encapsulatedPayload = Ipv6Payload.decode(in);
        return new EncapsulationPayload(header, encapsulatedPayload);
    }
}
