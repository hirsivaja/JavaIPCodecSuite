package com.github.hirsivaja.ip.ipv4.option;

import java.nio.ByteBuffer;

public record MtuProbe(short value) implements IpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.putShort(value);
    }

    @Override
    public int length() {
        return 4;
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.MTU_PROBE;
    }

    public static MtuProbe decode(ByteBuffer in){
        short value = in.getShort();
        return new MtuProbe(value);
    }
}
