package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RouterAdvertisement(
        byte currentHopLimit,
        byte flags,
        short routerLifetime,
        int reachableTime,
        int retransmissionTimer,
        List<NdpOption> options) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.put(currentHopLimit);
        out.put(flags);
        out.putShort(routerLifetime);
        out.putInt(reachableTime);
        out.putInt(retransmissionTimer);
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int length() {
        return BASE_LEN + 12 + options.stream().mapToInt(NdpOption::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        byte currentHopLimit = in.get();
        byte flags = in.get();
        short routerLifetime = in.getShort();
        int reachableTime = in.getInt();
        int retransmissionTimer = in.getInt();
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new RouterAdvertisement(currentHopLimit, flags, routerLifetime, reachableTime, retransmissionTimer, options);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Type.ROUTER_ADVERTISEMENT;
    }

    @Override
    public byte code() {
        return 0;
    }
}
