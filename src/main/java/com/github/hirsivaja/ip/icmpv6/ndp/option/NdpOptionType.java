package com.github.hirsivaja.ip.icmpv6.ndp.option;

public enum NdpOptionType {
    SOURCE_LINK_LAYER((byte) 0x01),
    TARGET_LINK_LAYER((byte) 0x02),
    PREFIX_INFORMATION((byte) 0x03),
    REDIRECTED_HEADER((byte) 0x04),
    MTU((byte) 0x05),
    SHORTCUT_LIMIT((byte) 0x06),
    ADVERTISEMENT_INTERVAL((byte) 0x07),
    HOME_AGENT_INFORMATION((byte) 0x08),
    SOURCE_ADDRESS_LIST((byte) 0x09),
    TARGET_ADDRESS_LIST((byte) 0x0A),
    CGA((byte) 0x0B),
    RSA_SIGNATURE((byte) 0x0C),
    TIMESTAMP((byte) 0x0D),
    NONCE((byte) 0x0E),
    TRUST_ANCHOR((byte) 0x0F),
    CERTIFICATE((byte) 0x10),
    IP_ADDRESS_OR_PREFIX((byte) 0x11),
    NEW_ROUTER_PREFIX_INFORMATION((byte) 0x12),
    LINK_LAYER_ADDRESS((byte) 0x13),
    NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT((byte) 0x14),
    PVD_ID_ROUTER_ADVERTISEMENT((byte) 0x15),
    MAP((byte) 0x17),
    ROUTE_INFORMATION((byte) 0x18),
    RECURSIVE_DNS_SERVER((byte) 0x19),
    RA_FLAGS_EXTENSION((byte) 0x1A),
    HANDOVER_KEY_REQUEST((byte) 0x1B),
    HANDOVER_KEY_REPLY((byte) 0x1C),
    HANDOVER_ASSIST_INFORMATION((byte) 0x1D),
    MOBILE_NODE_IDENTIFIER((byte) 0x1E),
    DNS_SEARCH_LIST((byte) 0x1F),
    PROXY_SIGNATURE((byte) 0x20),
    ADDRESS_REGISTRATION((byte) 0x21),
    SIXLOWPAN_CONTEXT((byte) 0x22),
    AUTHORITATIVE_BORDER_ROUTER((byte) 0x23),
    SIXLOWPAN_CAPABILITY_INDICATION((byte) 0x24),
    DHCP_CAPTIVE_PORTAL((byte) 0x25),
    PREF64((byte) 0x26),
    CRYPTO_ID_PARAMETERS((byte) 0x27),
    NDP_SIGNATURE((byte) 0x28),
    RESOURCE_DIRECTORY_ADDRESS((byte) 0x29),
    CONSISTENT_UPTIME((byte) 0x2A),
    CARD_REQUEST((byte) 0x8A),
    CARD_REPLY((byte) 0x8B),
    ENCRYPTED_DNS((byte) 0x90),
    EXPERIMENT_1((byte) 0xFD),
    EXPERIMENT_2((byte) 0xFE);

    private final byte type;

    NdpOptionType(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static NdpOptionType fromNdpOptionType(byte type) {
        for (NdpOptionType identifier : NdpOptionType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown NDP Option type " + type);
    }
}
