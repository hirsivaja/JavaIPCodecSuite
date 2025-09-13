package com.github.hirsivaja.ip.icmpv6.rpl;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayload;

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

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        RplPayload payload = RplPayload.decode(in, code);
        return new RplControlMessage(payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.RPL;
    }

    @Override
    public Icmpv6Code code() {
        return payload.code();
    }
}
