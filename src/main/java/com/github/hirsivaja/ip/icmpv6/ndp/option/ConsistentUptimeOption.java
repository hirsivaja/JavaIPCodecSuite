package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record ConsistentUptimeOption(short uptimeExponentAndMantissa, int flags) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort(uptimeExponentAndMantissa);
        out.putInt(flags);
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.CONSISTENT_UPTIME;
    }

    public static ConsistentUptimeOption decode(ByteBuffer in){
        short uptimeExponentAndMantissa = in.getShort();
        int flags = in.getInt();
        return new ConsistentUptimeOption(uptimeExponentAndMantissa, flags);
    }
}
