package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplTargetDescriptorOption implements RplOption {
    private static final int LEN = 4;
    private final int descriptor;

    public RplTargetDescriptorOption(int descriptor) {
        this.descriptor = descriptor;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) LEN);
        out.putInt(descriptor);
    }

    @Override
    public int getLength() {
        return 6;
    }

    @Override
    public RplOptionType getOptionType() {
        return RplOptionType.RPL_TARGET_DESCRIPTOR;
    }

    public static RplTargetDescriptorOption decode(ByteBuffer in){
        byte len = in.get();
        if(len != LEN){
            throw new IllegalArgumentException("Invalid length " + len);
        }
        int descriptor = in.getInt();
        return new RplTargetDescriptorOption(descriptor);
    }

    public int getDescriptor() {
        return descriptor;
    }
}
