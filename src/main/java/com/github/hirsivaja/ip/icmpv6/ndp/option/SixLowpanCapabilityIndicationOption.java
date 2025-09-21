package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record SixLowpanCapabilityIndicationOption(boolean g) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) (g ? 1 : 0));
        out.putInt(0); // RESERVED
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.SIXLOWPAN_CAPABILITY_INDICATION;
    }

    public static SixLowpanCapabilityIndicationOption decode(ByteBuffer in){
        boolean g = in.getShort() == 1;
        in.getInt(); // RESERVED
        return new SixLowpanCapabilityIndicationOption(g);
    }
}
