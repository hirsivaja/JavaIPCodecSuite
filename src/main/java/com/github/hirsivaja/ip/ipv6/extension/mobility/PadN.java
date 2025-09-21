package com.github.hirsivaja.ip.ipv6.extension.mobility;

import java.nio.ByteBuffer;

public record PadN(int size) implements MobilityOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(new byte[size]);
    }

    @Override
    public int length() {
        return 2 + size;
    }

    @Override
    public MobilityOptionType optionType() {
        return MobilityOptionType.PAD_N;
    }

    public static MobilityOption decode(ByteBuffer in) {
        int size = in.remaining();
        in.get(new byte[size]);
        return new PadN(size);
    }
}
