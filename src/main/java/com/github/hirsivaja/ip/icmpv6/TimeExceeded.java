package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;

public class TimeExceeded implements Icmpv6Message {
    private final byte code;
    private final byte[] payload;

    public TimeExceeded(byte code, byte[] payload) {
        this.code = code;
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        out.put(payload);
    }

    @Override
    public int getLength() {
        return 4 + payload.length;
    }

    public static Icmpv6Message decode(ByteBuffer in, byte code) {
        in.getInt(); // UNUSED
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new TimeExceeded(code, payload);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.TIME_EXCEEDED;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public byte[] getPayload() {
        return payload;
    }
}
