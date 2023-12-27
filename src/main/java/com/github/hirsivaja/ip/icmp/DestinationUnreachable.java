package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public class DestinationUnreachable implements IcmpMessage {
    private final byte code;
    private final byte[] payload;

    public DestinationUnreachable(byte code, byte[] payload) {
        this.code = code;
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        out.put(payload);
    }

    @Override
    public int getLength() {
        return 4 + payload.length;
    }

    public static IcmpMessage decode(ByteBuffer in, byte code) {
        in.getInt(); // UNUSED
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new DestinationUnreachable(code, payload);
    }

    @Override
    public IcmpType getType() {
        return IcmpType.DESTINATION_UNREACHABLE;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public byte[] getPayload() {
        return payload;
    }
}
