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
        out.put((byte) ((linkLayerAddress.length() + 2) / 8));
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
        byte len = in.get();
        byte[] linkLayerAddress = new byte[len * 8 - 2];
        in.get(linkLayerAddress);
        return new TargetLinkLayerOption(linkLayerAddress);
    }

    public byte[] rawLinkLayerAddress() {
        return linkLayerAddress.array();
    }
}
