package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record NeighborAdvertisementAcknowledgmentOption(byte optionCode, byte status) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(optionCode);
        out.put(status);
        out.putInt(0); // RESERVED
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT;
    }

    public static NeighborAdvertisementAcknowledgmentOption decode(ByteBuffer in){
        byte optionCode = in.get();
        byte status = in.get();
        in.getInt(); // RESERVED
        return new NeighborAdvertisementAcknowledgmentOption(optionCode, status);
    }
}
