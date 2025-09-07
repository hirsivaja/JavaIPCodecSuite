package com.github.hirsivaja.ip.icmpv6.rpl.option;

public enum RplOptionType {
    PAD_1((byte) 0x00),
    PAD_N((byte) 0x01),
    DAG_METRIC_CONTAINER((byte) 0x02),
    ROUTE_INFORMATION((byte) 0x03),
    DODAG_CONFIGURATION((byte) 0x04),
    RPL_TARGET((byte) 0x05),
    TRANSIT_INFORMATION((byte) 0x06),
    SOLICITED_INFORMATION((byte) 0x07),
    PREFIX_INFORMATION((byte) 0x08),
    RPL_TARGET_DESCRIPTOR((byte) 0x09);

    private final byte type;

    RplOptionType(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static RplOptionType fromRplOptionType(byte type) {
        for (RplOptionType identifier : RplOptionType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown RPL Option type " + type);
    }
}
