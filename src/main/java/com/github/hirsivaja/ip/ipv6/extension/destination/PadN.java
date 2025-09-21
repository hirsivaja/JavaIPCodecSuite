package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record PadN(int size) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) size);
        out.put(new byte[size]);
    }

    @Override
    public int length() {
        return 2 + size;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.PAD_N;
    }

    public static DestinationOption decode(ByteBuffer in) {
        int size = in.remaining();
        in.get(new byte[size]);
        return new PadN(size);
    }
}
