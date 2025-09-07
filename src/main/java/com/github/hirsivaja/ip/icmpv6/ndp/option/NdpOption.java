package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public interface NdpOption {

    void encode(ByteBuffer out);

    int length();

    NdpOptionType optionType();

    static NdpOption decode(ByteBuffer in) {
        NdpOptionType optionType = NdpOptionType.fromNdpOptionType(in.get());
        return switch (optionType) {
            case SOURCE_LINK_LAYER -> SourceLinkLayerOption.decode(in);
            case TARGET_LINK_LAYER -> TargetLinkLayerOption.decode(in);
            case PREFIX_INFORMATION -> PrefixInformationOption.decode(in);
            case REDIRECTED_HEADER -> RedirectedHeaderOption.decode(in);
            case MTU -> MtuOption.decode(in);
            default -> throw new IllegalArgumentException("Unexpected value: " + optionType);
        };
    }
}
