package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record Pad1() implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
    }

    @Override
    public int length() {
        return 1;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.PAD_1;
    }

    public static DestinationOption decode() {
        return new Pad1();
    }
}
