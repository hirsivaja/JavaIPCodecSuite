package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;

public class GenericIcmpv6Message implements Icmpv6Message {
    private final Icmpv6Type type;
    private final byte code;
    private final byte[] payload;

    public GenericIcmpv6Message(Icmpv6Type type, byte code, byte[] payload) {
        this.type = type;
        this.code = code;
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(payload);
    }

    @Override
    public int getLength() {
        return BASE_LEN + payload.length;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new GenericIcmpv6Message(type, code, payload);
    }

    @Override
    public Icmpv6Type getType() {
        return type;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public byte[] getPayload() {
        return payload;
    }
}
