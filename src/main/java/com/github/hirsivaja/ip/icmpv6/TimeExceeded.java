package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record TimeExceeded(Icmpv6Code code, ByteArray payload) implements Icmpv6Message {
    public TimeExceeded(Icmpv6Code code, byte[] payload) {
        this(code, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return 4 + payload.array().length;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        in.getInt(); // UNUSED
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new TimeExceeded(code, payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.TIME_EXCEEDED;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
