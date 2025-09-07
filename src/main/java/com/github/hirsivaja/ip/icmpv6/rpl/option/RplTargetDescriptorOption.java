package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public record RplTargetDescriptorOption(int descriptor) implements RplOption {
    private static final int LEN = 4;

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) LEN);
        out.putInt(descriptor);
    }

    @Override
    public int length() {
        return 6;
    }

    @Override
    public RplOptionType optionType() {
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
}
