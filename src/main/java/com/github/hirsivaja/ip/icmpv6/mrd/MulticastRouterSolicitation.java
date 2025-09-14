package com.github.hirsivaja.ip.icmpv6.mrd;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;

import java.nio.ByteBuffer;

public record MulticastRouterSolicitation() implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        // NOTHING TO ENCODE
    }

    @Override
    public int length() {
        return BASE_LEN;
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        return new MulticastRouterSolicitation();
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.MULTICAST_ROUTER_SOLICITATION;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.MULTICAST_ROUTER_SOLICITATION;
    }
}
