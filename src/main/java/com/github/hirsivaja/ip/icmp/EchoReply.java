package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record EchoReply(short identifier, short sequenceNumber, ByteArray payload) implements IcmpMessage {
    public EchoReply(short identifier, short sequenceNumber, byte[] payload) {
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
        return new EchoReply(identifier, sequenceNumber, payload);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.ECHO_REPLY;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.ECHO_REPLY;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
