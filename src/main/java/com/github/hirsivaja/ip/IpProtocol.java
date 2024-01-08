package com.github.hirsivaja.ip;

public enum IpProtocol {
    HOP_BY_HOP((byte) 0x00),
    ICMP((byte) 0x01),
    IGMP((byte) 0x02),
    TCP((byte) 0x06),
    UDP((byte) 0x11),
    ENCAPSULATION((byte) 0x29),
    ROUTING((byte) 0x2B),
    FRAGMENTATION((byte) 0x2C),
    ESP((byte) 0x32),
    AUTHENTICATION((byte) 0x33),
    ICMPV6((byte) 0x3A),
    NO_NEXT((byte) 0x3B),
    DESTINATION((byte) 0x3C);

    private final byte type;

    IpProtocol(byte type) {
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public static IpProtocol getType(byte type) {
        for (IpProtocol identifier : IpProtocol.values()) {
            if (identifier.getType() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown IP protocol type " + type);
    }
}
