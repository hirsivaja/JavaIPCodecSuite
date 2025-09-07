package com.github.hirsivaja.ip.icmpv6.rpl.payload;

public enum RplPayloadType {
    DIS((byte) 0x00),
    DIO((byte) 0x01),
    DAO((byte) 0x02),
    DAO_ACK((byte) 0x03),
    SECURE_DIS((byte) 0x80),
    SECURE_DIO((byte) 0x81),
    SECURE_DAO((byte) 0x82),
    SECURE_DAO_ACK((byte) 0x83),
    CONSISTENCY_CHECK((byte) 0x8A);

    private final byte type;

    RplPayloadType(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static RplPayloadType fromRplPayloadType(byte type) {
        for (RplPayloadType identifier : RplPayloadType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown RPL Payload type " + type);
    }
}
