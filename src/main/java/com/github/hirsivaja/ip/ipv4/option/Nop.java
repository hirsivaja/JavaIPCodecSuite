package com.github.hirsivaja.ip.ipv4.option;

import java.nio.ByteBuffer;

public record Nop() implements IpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
    }

    @Override
    public int length() {
        return 1;
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.NO_OPERATION;
    }

    public static IpOption decode() {
        return new Nop();
    }
}
