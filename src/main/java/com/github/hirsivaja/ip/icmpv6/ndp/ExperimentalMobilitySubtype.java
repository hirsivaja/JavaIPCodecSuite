package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record ExperimentalMobilitySubtype(
        Icmpv6Code code,
        byte subType,
        List<NdpOption> options) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.put(subType);
        out.put((byte) 0); // RESERVED
        out.putShort((short) 0); // RESERVED
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int length() {
        return 4 + options.stream().mapToInt(NdpOption::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        byte subType = in.get();
        in.get(); // RESERVED
        in.getShort(); // RESERVED
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new ExperimentalMobilitySubtype(code, subType, options);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.EXPERIMENTAL_MOBILE_PROTOCOLS;
    }
}
