package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record JumboPayload(int jumboPayloadLength) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.putInt(jumboPayloadLength);
    }

    @Override
    public int length() {
        return 6;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.JUMBO_PAYLOAD;
    }

    public static DestinationOption decode(ByteBuffer in) {
        int jumboPayloadLength = in.getInt();
        return new JumboPayload(jumboPayloadLength);
    }
}
