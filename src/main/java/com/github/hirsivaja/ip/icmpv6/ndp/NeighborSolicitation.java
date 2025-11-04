package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record NeighborSolicitation(Ipv6Address targetAddress, List<NdpOption> options) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        targetAddress.encode(out);
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int length() {
        return 20 + options.stream().mapToInt(NdpOption::length).sum();
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
    public Icmpv6Type type() {
        return Icmpv6Types.NEIGHBOR_SOLICITATION;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.NEIGHBOR_SOLICITATION;
    }
}
