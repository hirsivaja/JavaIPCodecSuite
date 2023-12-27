package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplTransitInformationOption implements RplOption {
    private final byte flags;
    private final byte pathControl;
    private final byte pathSequence;
    private final byte pathLifetime;
    private final byte[] parentAddress;

    public RplTransitInformationOption(byte flags, byte pathControl, byte pathSequence, byte pathLifetime,
                                       byte[] parentAddress) {
        this.flags = flags;
        this.pathControl = pathControl;
        this.pathSequence = pathSequence;
        this.pathLifetime = pathLifetime;
        this.parentAddress = parentAddress;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) (4 + parentAddress.length));
        out.put(flags);
        out.put(pathControl);
        out.put(pathSequence);
        out.put(pathLifetime);
        out.put(parentAddress);
    }

    @Override
    public int getLength() {
        return 6 + parentAddress.length;
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
        byte[] parentAddress = new byte[len - 4];
        in.get(parentAddress);
        return new RplTransitInformationOption(flags, pathControl, pathSequence, pathLifetime,
                parentAddress);
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

    public byte[] getParentAddress() {
        return parentAddress;
    }
}
