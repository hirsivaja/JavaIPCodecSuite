package com.github.hirsivaja.ip.icmpv6.rpl;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayload;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayloadType;

import java.nio.ByteBuffer;

public record RplControlMessage(RplPayload payload) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        payload.encode(out);
    }

    @Override
    public int length() {
        return BASE_LEN + payload.length();
    }

    public static Icmpv6Message decode(ByteBuffer in, RplPayloadType code) {
        RplPayload payload = RplPayload.decode(in, code);
        return new RplControlMessage(payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Type.RPL;
    }

    @Override
    public byte code() {
        return payload.type().type();
    }
}
