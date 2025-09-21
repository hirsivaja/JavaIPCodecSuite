package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.ipsec.EspHeader;

import java.nio.ByteBuffer;

public record EncapsulatingSecurityPayload(
        Ipv4Header header,
        EspHeader espHeader) implements Ipv4Payload {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        espHeader.encode(out);
    }

    @Override
    public int length() {
        return header.length() + espHeader.length();
    }

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
        EspHeader espHeader = EspHeader.decode(in);
        return new EncapsulatingSecurityPayload(header, espHeader);
    }
}
