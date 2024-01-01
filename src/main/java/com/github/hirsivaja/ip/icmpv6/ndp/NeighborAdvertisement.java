package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class NeighborAdvertisement implements Icmpv6Message {
    private final int flags;
    private final Ipv6Address targetAddress;
    private final List<NdpOption> options;

    public NeighborAdvertisement(int flags, Ipv6Address targetAddress, List<NdpOption> options) {
        this.flags = flags;
        this.targetAddress = targetAddress;
        this.options = options;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(flags);
        targetAddress.encode(out);
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int getLength() {
        return 20 + options.stream().mapToInt(NdpOption::getLength).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        int flags = in.getInt();
        Ipv6Address targetAddress = Ipv6Address.decode(in);
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new NeighborAdvertisement(flags, targetAddress, options);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.NEIGHBOR_ADVERTISEMENT;
    }

    @Override
    public byte getCode() {
        return 0;
    }

    public int getFlags() {
        return flags;
    }

    public Ipv6Address getTargetAddress() {
        return targetAddress;
    }

    public List<NdpOption> getOptions() {
        return options;
    }
}
