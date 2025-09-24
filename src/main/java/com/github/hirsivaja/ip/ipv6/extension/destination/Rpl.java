package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record Rpl(byte flags, byte rplInstanceId, short senderRank) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(flags);
        out.put(rplInstanceId);
        out.putShort(senderRank);
    }

    @Override
    public int length() {
        return 6;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.RPL;
    }

    public static DestinationOption decode(ByteBuffer in) {
        byte flags = in.get();
        byte rplInstanceId = in.get();
        short senderRank = in.getShort();
        return new Rpl(flags, rplInstanceId, senderRank);
    }
}
