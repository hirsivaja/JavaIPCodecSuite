package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record LinkLayerAddressOption(byte optionCode, ByteArray linkLayerAddress) implements NdpOption {

    public LinkLayerAddressOption(byte optionCode, byte[] linkLayerAddress) {
        this(optionCode, new ByteArray(linkLayerAddress));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(optionCode);
        out.put(linkLayerAddress.array());
    }

    @Override
    public int length() {
        return 3 + linkLayerAddress.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.LINK_LAYER_ADDRESS;
    }

    public static LinkLayerAddressOption decode(ByteBuffer in){
        byte optionCode = in.get();
        byte[] linkLayerAddress = new byte[in.remaining()];
        in.get(linkLayerAddress);
        return new LinkLayerAddressOption(optionCode, linkLayerAddress);
    }
}
