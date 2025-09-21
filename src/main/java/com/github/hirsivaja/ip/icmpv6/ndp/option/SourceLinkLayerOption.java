package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record SourceLinkLayerOption(ByteArray linkLayerAddress) implements NdpOption {

    public SourceLinkLayerOption(byte[] linkLayerAddress) {
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
        return NdpOptionType.SOURCE_LINK_LAYER;
    }

    public static SourceLinkLayerOption decode(ByteBuffer in){
        byte[] linkLayerAddress = new byte[in.remaining()];
        in.get(linkLayerAddress);
        return new SourceLinkLayerOption(linkLayerAddress);
    }

    public byte[] rawLinkLayerAddress() {
        return linkLayerAddress.array();
    }
}
