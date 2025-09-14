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
            case SHORTCUT_LIMIT -> ShortcutLimitOption.decode(in);
            case ADVERTISEMENT_INTERVAL -> AdvertisementIntervalOption.decode(in);
            case HOME_AGENT_INFORMATION -> HomeAgentInformationOption.decode(in);
            case SOURCE_ADDRESS_LIST -> SourceAddressListOption.decode(in);
            case TARGET_ADDRESS_LIST -> TargetAddressListOption.decode(in);
            case CGA -> CgaOption.decode(in);
            case RSA_SIGNATURE -> RsaSignatureOption.decode(in);
            case TIMESTAMP -> TimestampOption.decode(in);
            case NONCE -> NonceOption.decode(in);
            case TRUST_ANCHOR -> TrustAnchorOption.decode(in);
            case CERTIFICATE -> CertificateOption.decode(in);
            default -> throw new IllegalArgumentException("Unexpected value: " + optionType);
        };
    }
}
