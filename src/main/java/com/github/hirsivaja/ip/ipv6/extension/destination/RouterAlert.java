package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record RouterAlert(short value) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.putShort(value);
    }

    @Override
    public int length() {
        return 4;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.ROUTER_ALERT;
    }

    public static DestinationOption decode(ByteBuffer in) {
        short value = in.get();
        return new RouterAlert(value);
    }
}
