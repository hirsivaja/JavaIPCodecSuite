package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record Fmipv6Message(
        Icmpv6Code code,
        byte subType,
        short identifier,
        List<NdpOption> options) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.put(subType);
        out.put((byte) 0); // RESERVED
        out.putShort(identifier);
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + options.stream().mapToInt(NdpOption::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        byte subType = in.get();
        in.get(); // RESERVED
        short identifier = in.getShort();
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new Fmipv6Message(code, subType, identifier, options);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.FMIPV6_MESSAGES;
    }
}
