package com.github.hirsivaja.ip.ipv6.extension.mobility;

import java.nio.ByteBuffer;

public record Pad1() implements MobilityOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
    }

    @Override
    public int length() {
        return 1;
    }

    @Override
    public MobilityOptionType optionType() {
        return MobilityOptionType.PAD_1;
    }

    public static MobilityOption decode() {
        return new Pad1();
    }
}
