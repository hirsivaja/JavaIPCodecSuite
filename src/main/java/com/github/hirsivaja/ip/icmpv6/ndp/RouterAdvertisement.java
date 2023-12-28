package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class RouterAdvertisement implements Icmpv6Message {
    private final byte currentHopLimit;
    private final byte flags;
    private final short routerLifetime;
    private final int reachableTime;
    private final int retransmissionTimer;
    private final List<NdpOption> options;

    public RouterAdvertisement(byte currentHopLimit, byte flags, short routerLifetime, int reachableTime,
                               int retransmissionTimer, List<NdpOption> options) {
        this.currentHopLimit = currentHopLimit;
        this.flags = flags;
        this.routerLifetime = routerLifetime;
        this.reachableTime = reachableTime;
        this.retransmissionTimer = retransmissionTimer;
        this.options = options;
    }

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
    public int getLength() {
        return 12 + options.stream().mapToInt(NdpOption::getLength).sum();
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
    public Icmpv6Type getType() {
        return Icmpv6Type.ROUTER_ADVERTISEMENT;
    }

    @Override
    public byte getCode() {
        return 0;
    }

    public byte getCurrentHopLimit() {
        return currentHopLimit;
    }

    public byte getFlags() {
        return flags;
    }

    public short getRouterLifetime() {
        return routerLifetime;
    }

    public int getReachableTime() {
        return reachableTime;
    }

    public int getRetransmissionTimer() {
        return retransmissionTimer;
    }

    public List<NdpOption> getOptions() {
        return options;
    }
}
