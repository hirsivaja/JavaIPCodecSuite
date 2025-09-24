package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record AltMark(int flowMonIdAndFlags) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.putInt(flowMonIdAndFlags);
    }

    @Override
    public int length() {
        return 6;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.ALTMARK;
    }

    public static DestinationOption decode(ByteBuffer in) {
        int flowMonIdAndFlags = in.getInt();
        return new AltMark(flowMonIdAndFlags);
    }
}
