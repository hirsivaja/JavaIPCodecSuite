package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RouterSolicitation(List<NdpOption> options) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + options.stream().mapToInt(NdpOption::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        in.getInt(); // RESERVED
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new RouterSolicitation(options);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Type.ROUTER_SOLICITATION;
    }

    @Override
    public byte code() {
        return 0;
    }
}
