package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class RouterSolicitation implements Icmpv6Message {
    private final List<NdpOption> options;

    public RouterSolicitation(List<NdpOption> options) {
        this.options = options;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int getLength() {
        return 4 + options.stream().mapToInt(NdpOption::getLength).sum();
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
    public Icmpv6Type getType() {
        return Icmpv6Type.ROUTER_SOLICITATION;
    }

    @Override
    public byte getCode() {
        return 0;
    }

    public List<NdpOption> getOptions() {
        return options;
    }
}
