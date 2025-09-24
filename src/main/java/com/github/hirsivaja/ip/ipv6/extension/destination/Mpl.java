package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record Mpl(byte flags, byte sequence, ByteArray seedId) implements DestinationOption {

    private Mpl(byte flags, byte sequence, byte[] seedId) {
        this(flags, sequence, new ByteArray(seedId));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(flags);
        out.put(sequence);
        out.put(seedId.array());
    }

    @Override
    public int length() {
        return 4 + seedId.length();
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.MPL;
    }

    public static DestinationOption decode(ByteBuffer in) {
        byte flags = in.get();
        byte sequence = in.get();
        byte[] seedId = new byte[in.remaining()];
        in.get(seedId);
        return new Mpl(flags, sequence, seedId);
    }
}
