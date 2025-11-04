package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.ipsec.EspHeader;

import java.nio.ByteBuffer;

public record EspPayload(EspHeader espHeader) implements Ipv4Payload {

    @Override
    public void encode(ByteBuffer out) {
        espHeader.encode(out);
    }

    @Override
    public int length() {
        return espHeader.length();
    }

    public static EspPayload decode(ByteBuffer in) {
        EspHeader espHeader = EspHeader.decode(in);
        return new EspPayload(espHeader);
    }
}
