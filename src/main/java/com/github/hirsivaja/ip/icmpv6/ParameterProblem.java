package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;

public class ParameterProblem implements Icmpv6Message {
    private final byte code;
    private final int pointer;
    private final byte[] payload;

    public ParameterProblem(byte code, int pointer, byte[] payload) {
        this.code = code;
        this.pointer = pointer;
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(pointer);
        out.put(payload);
    }

    @Override
    public int getLength() {
        return BASE_LEN + 4 + payload.length;
    }

    public static Icmpv6Message decode(ByteBuffer in, byte code) {
        int pointer = in.getInt();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new ParameterProblem(code, pointer, payload);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.PARAMETER_PROBLEM;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public int getPointer() {
        return pointer;
    }

    public byte[] getPayload() {
        return payload;
    }
}
