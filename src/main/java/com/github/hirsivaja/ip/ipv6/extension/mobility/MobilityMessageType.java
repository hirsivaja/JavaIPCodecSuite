package com.github.hirsivaja.ip.ipv6.extension.mobility;

public enum MobilityMessageType {
    BINDING_REFRESH_REQUEST((byte) 0x00),
    HOME_TEST_INIT((byte) 0x01),
    CARE_OF_TEST_INIT((byte) 0x02),
    HOME_TEST((byte) 0x03),
    CARE_OF_TEST((byte) 0x04),
    BINDING_UPDATE((byte) 0x05),
    BINDING_ACKNOWLEDGEMENT((byte) 0x06),
    BINDING_ERROR((byte) 0x07);

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
