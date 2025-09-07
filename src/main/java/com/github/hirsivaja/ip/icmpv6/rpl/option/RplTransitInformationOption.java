package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public record RplTransitInformationOption(
        byte flags,
        byte pathControl,
        byte pathSequence,
        byte pathLifetime,
        Ipv6Address parentAddress) implements RplOption {

    public RplTransitInformationOption(byte flags, byte pathControl, byte pathSequence, byte pathLifetime) {
        this(flags, pathControl, pathSequence, pathLifetime, null);
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(flags);
        out.put(pathControl);
        out.put(pathSequence);
        out.put(pathLifetime);
        if(parentAddress != null) {
            parentAddress.encode(out);
        }
    }

    @Override
    public int length() {
        return 6 + (parentAddress == null ? 0 : 16);
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.TRANSIT_INFORMATION;
    }

    public static RplTransitInformationOption decode(ByteBuffer in){
        byte len = in.get();
        byte flags = in.get();
        byte pathControl = in.get();
        byte pathSequence = in.get();
        byte pathLifetime = in.get();
        if(len == 20) {
            return new RplTransitInformationOption(flags, pathControl, pathSequence, pathLifetime, Ipv6Address.decode(in));
        } else {
            return new RplTransitInformationOption(flags, pathControl, pathSequence, pathLifetime);
        }
    }
}
