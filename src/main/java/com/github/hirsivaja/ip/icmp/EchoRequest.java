package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record EchoRequest(short identifier, short sequenceNumber, ByteArray payload) implements IcmpMessage {

    public EchoRequest(short identifier, short sequenceNumber, byte[] payload) {
        this(identifier, sequenceNumber, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        out.putShort(sequenceNumber);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + payload.array().length;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        short identifier = in.getShort();
        short sequenceNumber = in.getShort();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new EchoRequest(identifier, sequenceNumber, payload);
    }

    @Override
    public IcmpType type() {
        return IcmpType.ECHO_REQUEST;
    }

    @Override
    public byte code() {
        return 0;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
