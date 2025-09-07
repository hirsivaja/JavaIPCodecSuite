package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record TimeExceeded(byte code, ByteArray payload) implements Icmpv6Message {
    public TimeExceeded(byte code, byte[] payload) {
        this(code, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + payload.array().length;
    }

    public static Icmpv6Message decode(ByteBuffer in, byte code) {
        in.getInt(); // UNUSED
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new TimeExceeded(code, payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Type.TIME_EXCEEDED;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
