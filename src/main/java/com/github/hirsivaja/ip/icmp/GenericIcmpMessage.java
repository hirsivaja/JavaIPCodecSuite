package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record GenericIcmpMessage(IcmpType type, IcmpCode code, ByteArray payload) implements IcmpMessage {

    public GenericIcmpMessage(IcmpType type, IcmpCode code, byte[] payload) {
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

    public static IcmpMessage decode(ByteBuffer in, IcmpType type, IcmpCode code) {
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new GenericIcmpMessage(type, code, payload);
    }

    @Override
    public IcmpType type() {
        return type;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
