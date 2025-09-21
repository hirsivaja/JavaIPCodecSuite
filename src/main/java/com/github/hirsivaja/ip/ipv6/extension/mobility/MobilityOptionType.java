package com.github.hirsivaja.ip.ipv6.extension.mobility;

public enum MobilityOptionType {
    PAD_1((byte) 0x00),
    PAD_N((byte) 0x01),
    BINDING_REFRESH_ADVICE((byte) 0x02),
    ALTERNATE_CARE_OF_ADDRESS((byte) 0x03),
    NONCE_INDICES((byte) 0x04),
    BINDING_AUTHORIZATION_DATA((byte) 0x05);

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
