package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class RedirectMessage implements Icmpv6Message {
    private final Ipv6Address targetAddress;
    private final Ipv6Address destinationAddress;
    private final List<NdpOption> options;

    public RedirectMessage(Ipv6Address targetAddress, Ipv6Address destinationAddress, List<NdpOption> options) {
        this.targetAddress = targetAddress;
        this.destinationAddress = destinationAddress;
        this.options = options;
    }

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
    public int getLength() {
        return 36 + options.stream().mapToInt(NdpOption::getLength).sum();
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
    public Icmpv6Type getType() {
        return Icmpv6Type.REDIRECT_MESSAGE;
    }

    @Override
    public byte getCode() {
        return 0;
    }

    public Ipv6Address getTargetAddress() {
        return targetAddress;
    }

    public Ipv6Address getDestinationAddress() {
        return destinationAddress;
    }

    public List<NdpOption> getOptions() {
        return options;
    }
}
