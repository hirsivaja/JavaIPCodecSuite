package com.github.hirsivaja.ip.icmpv6.mrd;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;

import java.nio.ByteBuffer;

public record MulticastRouterAdvertisement(
        byte advertisementInterval,
        short queryInterval,
        short robustnessVariable) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(queryInterval);
        out.putShort(robustnessVariable);
    }

    @Override
    public int length() {
        return 4;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        short queryInterval = in.getShort();
        short robustnessVariable = in.getShort();
        return new MulticastRouterAdvertisement(code.code(), queryInterval, robustnessVariable);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.MULTICAST_ROUTER_ADVERTISEMENT;
    }

    @Override
    public Icmpv6Code code() {
        return new Icmpv6Code.GenericIcmpv6Code(Icmpv6Types.MULTICAST_ROUTER_ADVERTISEMENT, advertisementInterval);
    }
}
