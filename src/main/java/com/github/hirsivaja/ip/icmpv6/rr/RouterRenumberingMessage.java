package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;

import java.nio.ByteBuffer;

public record RouterRenumberingMessage(
        RouterRenumberingHeader rrHeader,
        RouterRenumberingBody rrBody) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        rrHeader.encode(out);
        rrBody.encode(out);
    }

    @Override
    public int length() {
        return BASE_LEN + rrHeader.length() + rrBody.length();
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        RouterRenumberingHeader rrHeader = RouterRenumberingHeader.decode(in);
        RouterRenumberingBody rrBody = RouterRenumberingBody.decode(in, code);
        return new RouterRenumberingMessage(rrHeader, rrBody);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.ROUTER_RENUMBERING;
    }

    @Override
    public Icmpv6Code code() {
        return rrBody.code();
    }
}
