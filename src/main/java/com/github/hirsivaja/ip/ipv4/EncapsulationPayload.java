package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record EncapsulationPayload(Ipv4Header header, IpPayload encapsulatedPayload) implements Ipv4Payload {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        encapsulatedPayload.encode(out);
    }

    @Override
    public int length() {
        return header.length() + encapsulatedPayload.length();
    }

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
        IpPayload encapsulatedPayload = Ipv6Payload.decode(in);
        return new EncapsulationPayload(header, encapsulatedPayload);
    }
}
