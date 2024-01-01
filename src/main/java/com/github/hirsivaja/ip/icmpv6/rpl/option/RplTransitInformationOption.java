package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public class RplTransitInformationOption implements RplOption {
    private final byte flags;
    private final byte pathControl;
    private final byte pathSequence;
    private final byte pathLifetime;
    private final Ipv6Address parentAddress;

    public RplTransitInformationOption(byte flags, byte pathControl, byte pathSequence, byte pathLifetime) {
        this(flags, pathControl, pathSequence, pathLifetime, null);
    }

    public RplTransitInformationOption(byte flags, byte pathControl, byte pathSequence, byte pathLifetime,
                                       Ipv6Address parentAddress) {
        this.flags = flags;
        this.pathControl = pathControl;
        this.pathSequence = pathSequence;
        this.pathLifetime = pathLifetime;
        this.parentAddress = parentAddress;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) (getLength() - 2));
        out.put(flags);
        out.put(pathControl);
        out.put(pathSequence);
        out.put(pathLifetime);
        if(parentAddress != null) {
            parentAddress.encode(out);
        }
    }

    @Override
    public int getLength() {
        return 6 + (parentAddress == null ? 0 : 16);
    }

    @Override
    public RplOptionType getOptionType() {
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

    public byte getFlags() {
        return flags;
    }

    public byte getPathControl() {
        return pathControl;
    }

    public byte getPathSequence() {
        return pathSequence;
    }

    public byte getPathLifetime() {
        return pathLifetime;
    }

    public Ipv6Address getParentAddress() {
        return parentAddress;
    }
}
