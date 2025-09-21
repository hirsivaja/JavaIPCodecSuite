package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record TargetLinkLayerOption(ByteArray linkLayerAddress) implements NdpOption {

    public TargetLinkLayerOption(byte[] linkLayerAddress) {
        this(new ByteArray(linkLayerAddress));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(linkLayerAddress.array());
    }

    @Override
    public int length() {
        return linkLayerAddress.length() + 2;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.TARGET_LINK_LAYER;
    }

    public static TargetLinkLayerOption decode(ByteBuffer in){
        byte[] linkLayerAddress = new byte[in.remaining()];
        in.get(linkLayerAddress);
        return new TargetLinkLayerOption(linkLayerAddress);
    }

    public byte[] rawLinkLayerAddress() {
        return linkLayerAddress.array();
    }
}
