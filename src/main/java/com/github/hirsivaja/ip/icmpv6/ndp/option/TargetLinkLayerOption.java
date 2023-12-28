package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public class TargetLinkLayerOption implements NdpOption {
    private final byte[] linkLayerAddress;

    public TargetLinkLayerOption(byte[] linkLayerAddress) {
        this.linkLayerAddress = linkLayerAddress;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) ((linkLayerAddress.length + 2) / 8));
        out.put(linkLayerAddress);
    }

    @Override
    public int getLength() {
        return linkLayerAddress.length + 2;
    }

    @Override
    public NdpOptionType getOptionType() {
        return NdpOptionType.TARGET_LINK_LAYER;
    }

    public static TargetLinkLayerOption decode(ByteBuffer in){
        byte len = in.get();
        byte[] linkLayerAddress = new byte[len * 8 - 2];
        in.get(linkLayerAddress);
        return new TargetLinkLayerOption(linkLayerAddress);
    }

    public byte[] getLinkLayerAddress() {
        return linkLayerAddress;
    }
}
