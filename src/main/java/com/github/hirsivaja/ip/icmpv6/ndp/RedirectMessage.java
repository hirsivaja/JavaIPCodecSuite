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

public record RedirectMessage(
        Ipv6Address targetAddress,
        Ipv6Address destinationAddress,
        List<NdpOption> options) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(0);
        targetAddress.encode(out);
        destinationAddress.encode(out);
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int length() {
        return 36 + options.stream().mapToInt(NdpOption::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        in.getInt(); // RESERVED
        Ipv6Address targetAddress = Ipv6Address.decode(in);
        Ipv6Address destinationAddress = Ipv6Address.decode(in);
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new RedirectMessage(targetAddress, destinationAddress, options);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.REDIRECT_MESSAGE;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.REDIRECT_MESSAGE;
    }
}
