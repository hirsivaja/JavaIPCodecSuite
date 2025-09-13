package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public record RouterSolicitation() implements IcmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0); // UNUSED
    }

    @Override
    public int length() {
        return BASE_LEN + 4;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        in.getInt(); // UNUSED
        return new RouterSolicitation();
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.ROUTER_SOLICITATION;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.ROUTER_SOLICITATION;
    }
}
