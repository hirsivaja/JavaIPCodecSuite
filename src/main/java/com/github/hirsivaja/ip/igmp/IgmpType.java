package com.github.hirsivaja.ip.igmp;

public enum IgmpType {
    CREATE_GROUP_REQUEST((byte) 0x01),
    CREATE_GROUP_REPLY((byte) 0x02),
    JOIN_GROUP_REQUEST((byte) 0x03),
    JOIN_GROUP_REPLY((byte) 0x04),
    LEAVE_GROUP_REQUEST((byte) 0x05),
    LEAVE_GROUP_REPLY((byte) 0x06),
    CONFIRM_GROUP_REQUEST((byte) 0x07),
    CONFIRM_GROUP_REPLY((byte) 0x08),
    MEMBERSHIP_QUERY((byte) 0x11),
    MEMBERSHIP_REPORT_V1((byte) 0x12),
    MEMBERSHIP_REPORT_V2((byte) 0x16),
    LEAVE_GROUP_V2((byte) 0x17),
    MEMBERSHIP_REPORT_V3((byte) 0x22);

    private final byte type;

    IgmpType(byte type) {
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public static IgmpType getType(byte type) {
        for (IgmpType identifier : IgmpType.values()) {
            if (identifier.getType() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown IGMP type " + type);
    }
}
