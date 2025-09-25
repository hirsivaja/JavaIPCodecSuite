package com.github.hirsivaja.ip.ipv6.extension.mobility;

public enum MobilityOptionType {
    PAD_1((byte) 0x00),
    PAD_N((byte) 0x01),
    BINDING_REFRESH_ADVICE((byte) 0x02),
    ALTERNATE_CARE_OF_ADDRESS((byte) 0x03),
    NONCE_INDICES((byte) 0x04),
    BINDING_AUTHORIZATION_DATA((byte) 0x05),
    MOBILE_NETWORK_PREFIX((byte) 0x06),
    MOBILITY_HEADER_LINK_LAYER_ADDRESS((byte) 0x07),
    MN_ID((byte) 0x08),
    AUTH((byte) 0x09),
    MESG_ID((byte) 0x0A),
    CGA_PARAMETERS_REQUEST((byte) 0x0B),
    CGA_PARAMETERS((byte) 0x0C),
    SIGNATURE((byte) 0x0D),
    PERMANENT_HOME_KEYGEN_TOKEN((byte) 0x0E),
    CARE_OF_TEST_INIT((byte) 0x0F),
    CARE_OF_TEST((byte) 0x10),
    DNS_UPDATE((byte) 0x11),
    EXPERIMENTAL((byte) 0x12),
    VENDOR_SPECIFIC((byte) 0x13),
    SERVICE_SELECTION((byte) 0x14),
    BINDING_AUTHORIZATION_DATA_FOR_FMIPV6((byte) 0x15),
    HOME_NETWORK_PREFIX((byte) 0x16),
    HANDOFF_INDICATOR((byte) 0x17),
    ACCESS_TECHNOLOGY_TYPE((byte) 0x18),
    MOBILE_NODE_LINK_LAYER_IDENTIFIER((byte) 0x19),
    LINK_LOCAL_ADDRESS((byte) 0x1A),
    TIMESTAMP((byte) 0x1B),
    RESTART_COUNTER((byte) 0x1C),
    IPV4_HOME_ADDRESS((byte) 0x1D),
    IPV4_ADDRESS_ACKNOWLEDGEMENT((byte) 0x1E),
    NAT_DETECTION((byte) 0x1F),
    IPV4_CARE_OF_ADDRESS((byte) 0x20),
    GRE_KEY((byte) 0x21),
    MOBILITY_HEADER_IPV6_ADDRESS_OR_PREFIX((byte) 0x22),
    BINDING_IDENTIFIER((byte) 0x23),
    IPV4_HOME_ADDRESS_REQUEST((byte) 0x24),
    IPV4_HOME_ADDRESS_REPLY((byte) 0x25),
    IPV4_DEFAULT_ROUTER_ADDRESS((byte) 0x26),
    IPV4_DHCP_SUPPORT_MODE((byte) 0x27),
    CONTEXT_REQUEST((byte) 0x28),
    LOCAL_MOBILITY_ANCHOR_ADDRESS((byte) 0x29),
    MOBILE_NODE_LINK_LOCAL_ADDRESS_INTERFACE_IDENTIFIER((byte) 0x2A),
    TRANSIENT_BINDING((byte) 0x2B),
    FLOW_SUMMARY((byte) 0x2C),
    FLOW_IDENTIFICATION((byte) 0x2D),
    REDIRECT_CAPABILITY((byte) 0x2E),
    REDIRECT((byte) 0x2F),
    LOAD_INFORMATION((byte) 0x30),
    ALTERNATE_IPV4_CARE_OF_ADDRESS((byte) 0x31),
    MOBILE_NODE_GROUP_IDENTIFIER((byte) 0x32),
    MAG_IPV6_ADDRESS((byte) 0x33),
    ACCESS_NETWORK_IDENTIFIER((byte) 0x34),
    IPV4_TRAFFIC_OFFLOAD_SELECTOR((byte) 0x35),
    DYNAMIC_IP_MULTICAST_SELECTOR((byte) 0x36),
    DELEGATED_MOBILE_NETWORK_PREFIX((byte) 0x37),
    ACTIVE_MULTICAST_SUBSCRIPTION_IPV4((byte) 0x38),
    ACTIVE_MULTICAST_SUBSCRIPTION_IPV6((byte) 0x39),
    QUALITY_OF_SERVICE((byte) 0x3A),
    LMA_USER_PLANE_ADDRESS((byte) 0x3B),
    MULTICAST((byte) 0x3C),
    MULTICAST_ACKNOWLEDGEMENT((byte) 0x3D),
    LMA_CONTROLLED_MAG_PARAMETERS((byte) 0x3E),
    MAG_MULTIPATH_BINDING((byte) 0x3F),
    MAG_IDENTIFIER((byte) 0x40),
    ANCHORED_PREFIX((byte) 0x41),
    LOCAL_PREFIX((byte) 0x42),
    PREVIOUS_MAAR((byte) 0x43),
    SERVING_MAAR((byte) 0x44),
    DLIF_LINK_LOCAL_ADDRESS((byte) 0x45),
    DLIF_LINK_LAYER_ADDRESS((byte) 0x46);

    private final byte type;

    MobilityOptionType(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static MobilityOptionType fromType(byte type) {
        for (MobilityOptionType identifier : MobilityOptionType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown Mobility Header Option type " + type);
    }
}
