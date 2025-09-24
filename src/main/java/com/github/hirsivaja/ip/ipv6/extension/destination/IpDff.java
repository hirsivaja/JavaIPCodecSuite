package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record IpDff(byte flags, short sequenceNumber) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(flags);
        out.putShort(sequenceNumber);
        out.put((byte) 0); // PADDING
    }

    @Override
    public int length() {
        return 6;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.IP_DFF;
    }

    public static DestinationOption decode(ByteBuffer in) {
        byte flags = in.get();
        short sequenceNumber = in.getShort();
        in.get(); // PADDING
        return new IpDff(flags, sequenceNumber);
    }
}
