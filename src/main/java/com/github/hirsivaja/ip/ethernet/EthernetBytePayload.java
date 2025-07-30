package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.IpUtils;

import java.nio.ByteBuffer;

public class EthernetBytePayload implements EthernetPayload {
    private final byte[] payload;

    public EthernetBytePayload(byte[] payload) {
        this.payload = payload;
    }

    public void encode(ByteBuffer out) {
        out.put(payload);
    }

    public int getLength() {
        return payload.length;
    }

    public static EthernetBytePayload decode(ByteBuffer in, int len) {
        byte[] payload = new byte[len];
        in.get(payload);
        return new EthernetBytePayload(payload);
    }

    public byte[] getPayload() {
        return payload;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "(" + IpUtils.printHexBinary(payload) + ")";
    }
}
