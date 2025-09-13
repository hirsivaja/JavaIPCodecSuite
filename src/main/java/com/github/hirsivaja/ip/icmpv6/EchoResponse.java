package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record EchoResponse(short identifier, short sequenceNumber, ByteArray payload) implements Icmpv6Message {

    public EchoResponse(short identifier, short sequenceNumber, byte[] payload) {
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

    public static Icmpv6Message decode(ByteBuffer in) {
        short identifier = in.getShort();
        short sequenceNumber = in.getShort();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new EchoResponse(identifier, sequenceNumber, payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.ECHO_RESPONSE;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.ECHO_RESPONSE;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
