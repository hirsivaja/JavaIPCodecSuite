package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public class GenericIcmpMessage implements IcmpMessage {
    private final IcmpType type;
    private final byte code;
    private final byte[] payload;

    public GenericIcmpMessage(IcmpType type, byte code, byte[] payload) {
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

    public static IcmpMessage decode(ByteBuffer in, IcmpType type, byte code) {
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new GenericIcmpMessage(type, code, payload);
    }

    @Override
    public IcmpType getType() {
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
