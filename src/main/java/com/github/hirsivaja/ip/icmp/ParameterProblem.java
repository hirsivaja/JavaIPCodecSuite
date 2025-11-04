package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record ParameterProblem(IcmpCode code, byte pointer, ByteArray payload) implements IcmpMessage {
    public ParameterProblem(IcmpCode code, byte pointer, byte[] payload) {
        this(code, pointer, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(pointer);
        out.put((byte) 0); // UNUSED
        out.putShort((short) 0); // UNUSED
        out.put(payload.array());
    }

    @Override
    public int length() {
        return 4 + payload.array().length;
    }

    public static IcmpMessage decode(ByteBuffer in, IcmpCode code) {
        byte pointer = in.get();
        in.get(); // UNUSED
        in.getShort(); // UNUSED
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new ParameterProblem(code, pointer, payload);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.PARAMETER_PROBLEM;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
