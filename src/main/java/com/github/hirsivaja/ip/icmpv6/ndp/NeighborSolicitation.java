package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class NeighborSolicitation implements Icmpv6Message {
    private final Ipv6Address targetAddress;
    private final List<NdpOption> options;

    public NeighborSolicitation(Ipv6Address targetAddress, List<NdpOption> options) {
        this.targetAddress = targetAddress;
        this.options = options;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
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
        in.getInt(); // RESERVED
        Ipv6Address targetAddress = Ipv6Address.decode(in);
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new NeighborSolicitation(targetAddress, options);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.NEIGHBOR_SOLICITATION;
    }

    @Override
    public byte getCode() {
        return 0;
    }

    public Ipv6Address getTargetAddress() {
        return targetAddress;
    }

    public List<NdpOption> getOptions() {
        return options;
    }
}
