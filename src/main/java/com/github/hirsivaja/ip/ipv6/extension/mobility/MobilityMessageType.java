package com.github.hirsivaja.ip.ipv6.extension.mobility;

public enum MobilityMessageType {
    BINDING_REFRESH_REQUEST((byte) 0x00),
    HOME_TEST_INIT((byte) 0x01),
    CARE_OF_TEST_INIT((byte) 0x02),
    HOME_TEST((byte) 0x03),
    CARE_OF_TEST((byte) 0x04),
    BINDING_UPDATE((byte) 0x05),
    BINDING_ACKNOWLEDGEMENT((byte) 0x06),
    BINDING_ERROR((byte) 0x07),
    FAST_BINDING_UPDATE((byte) 0x08),
    FAST_BINDING_ACKNOWLEDGEMENT((byte) 0x09),
    FAST_NEIGHBOR_ADVERTISEMENT((byte) 0x0A),
    EXPERIMENTAL_MOBILITY_HEADER((byte) 0x0B),
    HOME_AGENT_SWITCH_MESSAGE((byte) 0x0C),
    HEARTBEAT_MESSAGE((byte) 0x0D),
    HANDOVER_INITIATE_MESSAGE((byte) 0x0E),
    HANDOVER_ACKNOWLEDGE_MESSAGE((byte) 0x0F),
    BINDING_REVOCATION_MESSAGE((byte) 0x10),
    LOCALIZED_ROUTING_INITIATION((byte) 0x11),
    LOCALIZED_ROUTING_ACKNOWLEDGEMENT((byte) 0x12),
    UPDATE_NOTIFICATION((byte) 0x13),
    UPDATE_NOTIFICATION_ACKNOWLEDGEMENT((byte) 0x14),
    FLOW_BINDING_MESSAGE((byte) 0x15),
    SUBSCRIPTION_QUERY((byte) 0x16),
    SUBSCRIPTION_RESPONSE((byte) 0x17);

    private final byte type;

    MobilityMessageType(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static MobilityMessageType fromType(byte type) {
        for (MobilityMessageType identifier : MobilityMessageType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown Mobility Header Message type " + type);
    }
}
