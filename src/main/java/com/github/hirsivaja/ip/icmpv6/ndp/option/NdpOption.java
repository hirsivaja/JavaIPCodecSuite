package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public interface NdpOption {

    void encode(ByteBuffer out);

    int length();

    NdpOptionType optionType();

    static NdpOption decode(ByteBuffer in) {
        NdpOptionType optionType = NdpOptionType.fromNdpOptionType(in.get());
        int optionLength = Byte.toUnsignedInt(in.get()) * 8;
        byte[] optionBytes = new byte[optionLength - 2];
        in.get(optionBytes);
        ByteBuffer optionBuffer = ByteBuffer.wrap(optionBytes);
        return switch (optionType) {
            case SOURCE_LINK_LAYER -> SourceLinkLayerOption.decode(optionBuffer);
            case TARGET_LINK_LAYER -> TargetLinkLayerOption.decode(optionBuffer);
            case PREFIX_INFORMATION -> PrefixInformationOption.decode(optionBuffer);
            case REDIRECTED_HEADER -> RedirectedHeaderOption.decode(optionBuffer);
            case MTU -> MtuOption.decode(optionBuffer);
            case SHORTCUT_LIMIT -> ShortcutLimitOption.decode(optionBuffer);
            case ADVERTISEMENT_INTERVAL -> AdvertisementIntervalOption.decode(optionBuffer);
            case HOME_AGENT_INFORMATION -> HomeAgentInformationOption.decode(optionBuffer);
            case SOURCE_ADDRESS_LIST -> SourceAddressListOption.decode(optionBuffer);
            case TARGET_ADDRESS_LIST -> TargetAddressListOption.decode(optionBuffer);
            case CGA -> CgaOption.decode(optionBuffer);
            case RSA_SIGNATURE -> RsaSignatureOption.decode(optionBuffer);
            case TIMESTAMP -> TimestampOption.decode(optionBuffer);
            case NONCE -> NonceOption.decode(optionBuffer);
            case TRUST_ANCHOR -> TrustAnchorOption.decode(optionBuffer);
            case CERTIFICATE -> CertificateOption.decode(optionBuffer);
            case IP_ADDRESS_OR_PREFIX -> IpAddressOrPrefixOption.decode(optionBuffer);
            case LINK_LAYER_ADDRESS -> LinkLayerAddressOption.decode(optionBuffer);
            case NEW_ROUTER_PREFIX_INFORMATION -> NewRouterPrefixInformationOption.decode(optionBuffer);
            case NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT -> NeighborAdvertisementAcknowledgmentOption.decode(optionBuffer);
            case PVD_ID_ROUTER_ADVERTISEMENT -> PvdIdRouterAdvertisementOption.decode(optionBuffer);
            case MAP -> MapOption.decode(optionBuffer);
            case ROUTE_INFORMATION -> RouteInformationOption.decode(optionBuffer);
            case RECURSIVE_DNS_SERVER -> RecursiveDnsServerOption.decode(optionBuffer);
            case RA_FLAGS_EXTENSION -> FlagsExtensionOption.decode(optionBuffer);
            case HANDOVER_KEY_REQUEST -> HandoverKeyRequestOption.decode(optionBuffer);
            case HANDOVER_KEY_REPLY -> HandoverKeyReplyOption.decode(optionBuffer);
            case HANDOVER_ASSIST_INFORMATION -> HandoverAssistInformationOption.decode(optionBuffer);
            case MOBILE_NODE_IDENTIFIER -> MobileNodeIdentifierOption.decode(optionBuffer);
            case DNS_SEARCH_LIST -> DnsSearchListOption.decode(optionBuffer);
            case PROXY_SIGNATURE -> ProxySignatureOption.decode(optionBuffer);
            case ADDRESS_REGISTRATION -> AddressRegistrationOption.decode(optionBuffer);
            case SIXLOWPAN_CONTEXT -> SixLowpanContextOption.decode(optionBuffer);
            case AUTHORITATIVE_BORDER_ROUTER -> AuthoritativeBorderRouterOption.decode(optionBuffer);
            case SIXLOWPAN_CAPABILITY_INDICATION -> SixLowpanCapabilityIndicationOption.decode(optionBuffer);
            case DHCP_CAPTIVE_PORTAL -> DhcpCaptivePortalOption.decode(optionBuffer);
            case PREF64 -> Pref64Option.decode(optionBuffer);
            case CRYPTO_ID_PARAMETERS -> CryptoIdParametersOption.decode(optionBuffer);
            case NDP_SIGNATURE -> NdpSignatureOption.decode(optionBuffer);
            case RESOURCE_DIRECTORY_ADDRESS -> ResourceDirectoryAddressOption.decode(optionBuffer);
            case CONSISTENT_UPTIME -> ConsistentUptimeOption.decode(optionBuffer);
            case CARD_REQUEST -> CardRequestOption.decode(optionBuffer);
            case CARD_REPLY -> CardReplyOption.decode(optionBuffer);
            case ENCRYPTED_DNS -> EncryptedDnsOption.decode(optionBuffer);
            default -> GenericNdpOption.decode(optionBuffer, optionType);
        };
    }
}
