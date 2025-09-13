package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record ParameterProblem(Icmpv6Code code, int pointer, ByteArray payload) implements Icmpv6Message {

    public ParameterProblem(Icmpv6Code code, int pointer, byte[] payload) {
        this(code, pointer, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(pointer);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + payload.array().length;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        int pointer = in.getInt();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new ParameterProblem(code, pointer, payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.PARAMETER_PROBLEM;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
