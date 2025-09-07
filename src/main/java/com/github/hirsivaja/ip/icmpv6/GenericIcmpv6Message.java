package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record GenericIcmpv6Message(Icmpv6Type type, byte code, ByteArray payload) implements Icmpv6Message {

    public GenericIcmpv6Message(Icmpv6Type type, byte code, byte[] payload) {
        this(type, code, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(payload.array());
    }

    @Override
    public int length() {
        return BASE_LEN + payload.array().length;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new GenericIcmpv6Message(type, code, payload);
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
