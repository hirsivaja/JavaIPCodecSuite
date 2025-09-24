package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record MinimumPathMtu(short minPmtu, short rtnPmtu, boolean r) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        short rtnPmtuOut = (short) (rtnPmtu << 1);
        if(r) {
            rtnPmtuOut |= 1;
        }
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.putShort(minPmtu);
        out.putShort(rtnPmtuOut);
    }

    @Override
    public int length() {
        return 6;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.MINIMUM_PATH_MTU;
    }

    public static DestinationOption decode(ByteBuffer in) {
        short minPmtu = in.getShort();
        short rtnPmtu = in.getShort();
        boolean r = (rtnPmtu & 1) > 0;
        rtnPmtu = (short) (rtnPmtu >> 1 & 0x7FFF);
        return new MinimumPathMtu(minPmtu, rtnPmtu, r);
    }
}
