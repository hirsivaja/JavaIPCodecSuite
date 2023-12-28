package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public interface NdpOption {

    void encode(ByteBuffer out);

    int getLength();

    NdpOptionType getOptionType();

    static NdpOption decode(ByteBuffer in) {
        NdpOptionType optionType = NdpOptionType.getNdpOptionType(in.get());
        switch (optionType) {
            case SOURCE_LINK_LAYER: return SourceLinkLayerOption.decode(in);
            case TARGET_LINK_LAYER: return TargetLinkLayerOption.decode(in);
            case PREFIX_INFORMATION: return PrefixInformationOption.decode(in);
            case REDIRECTED_HEADER: return RedirectedHeaderOption.decode(in);
            case MTU: return MtuOption.decode(in);
            default: throw new IllegalArgumentException("Unexpected value: " + optionType);
        }
    }
}
