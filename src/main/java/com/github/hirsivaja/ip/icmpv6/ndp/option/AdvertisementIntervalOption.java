package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record AdvertisementIntervalOption(int advertisementInterval) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0);
        out.putInt(advertisementInterval);
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.ADVERTISEMENT_INTERVAL;
    }

    public static AdvertisementIntervalOption decode(ByteBuffer in){
        in.getShort(); // RESERVED
        int advertisementInterval = in.getInt();
        return new AdvertisementIntervalOption(advertisementInterval);
    }
}
