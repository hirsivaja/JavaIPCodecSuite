package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class NeighborSolicitation implements Icmpv6Message {
    private final byte[] targetAddress;
    private final List<NdpOption> options;

    public NeighborSolicitation(byte[] targetAddress, List<NdpOption> options) {
        this.targetAddress = targetAddress;
        this.options = options;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        out.put(targetAddress);
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
        byte[] targetAddress = new byte[16];
        in.get(targetAddress);
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

    public byte[] getTargetAddress() {
        return targetAddress;
    }

    public List<NdpOption> getOptions() {
        return options;
    }
}
