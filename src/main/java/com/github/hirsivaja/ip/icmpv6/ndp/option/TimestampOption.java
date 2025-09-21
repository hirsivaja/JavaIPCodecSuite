package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record TimestampOption(long timestamp) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0);
        out.putInt(0);
        out.putLong(timestamp);
    }

    @Override
    public int length() {
        return 16;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.TIMESTAMP;
    }

    public static TimestampOption decode(ByteBuffer in){
        in.getShort(); // RESERVED
        in.getInt(); // RESERVED
        long timestamp = in.getLong();
        return new TimestampOption(timestamp);
    }
}
