package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record SourceQuench(ByteArray payload) implements IcmpMessage {
    public SourceQuench(byte[] payload) {
        this(new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0); // UNUSED
        out.put(payload.array());
    }

    @Override
    public int length() {
        return 4 + payload.array().length;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        in.getInt(); // UNUSED
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new SourceQuench(payload);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.SOURCE_QUENCH;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.SOURCE_QUENCH;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
