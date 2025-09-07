package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.ByteArray;

import java.nio.ByteBuffer;

public record EthernetBytePayload(ByteArray payload) implements EthernetPayload {

    public EthernetBytePayload(byte[] payload) {
        this(new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(payload.array());
    }

    @Override
    public int length() {
        return payload.array().length;
    }

    public static EthernetBytePayload decode(ByteBuffer in, int len) {
        byte[] payload = new byte[len];
        in.get(payload);
        return new EthernetBytePayload(payload);
    }
}
