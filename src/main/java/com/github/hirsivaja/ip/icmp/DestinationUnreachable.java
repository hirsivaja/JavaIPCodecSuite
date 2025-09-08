package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record DestinationUnreachable(byte code, ByteArray payload) implements IcmpMessage {
    public DestinationUnreachable(byte code, byte[] payload) {
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

    public static IcmpMessage decode(ByteBuffer in, byte code) {
        in.getInt(); // UNUSED
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new DestinationUnreachable(code, payload);
    }

    @Override
    public IcmpType type() {
        return IcmpType.DESTINATION_UNREACHABLE;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
