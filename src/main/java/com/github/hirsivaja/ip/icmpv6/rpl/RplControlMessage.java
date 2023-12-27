package com.github.hirsivaja.ip.icmpv6.rpl;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayload;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayloadType;

import java.nio.ByteBuffer;

public class RplControlMessage implements Icmpv6Message {
    private final RplPayload payload;

    public RplControlMessage(RplPayload payload){
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        payload.encode(out);
    }

    @Override
    public int getLength() {
        return payload.getLength();
    }

    public static Icmpv6Message decode(ByteBuffer in, RplPayloadType code) {
        RplPayload payload = RplPayload.decode(in, code);
        return new RplControlMessage(payload);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.RPL;
    }

    @Override
    public byte getCode() {
        return payload.getType().getType();
    }

    public RplPayload getPayload() {
        return payload;
    }
}
