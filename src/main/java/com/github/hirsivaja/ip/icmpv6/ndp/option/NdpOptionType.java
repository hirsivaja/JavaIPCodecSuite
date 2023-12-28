package com.github.hirsivaja.ip.icmpv6.ndp.option;

public enum NdpOptionType {
    SOURCE_LINK_LAYER((byte) 0x01),
    TARGET_LINK_LAYER((byte) 0x02),
    PREFIX_INFORMATION((byte) 0x03),
    REDIRECTED_HEADER((byte) 0x04),
    MTU((byte) 0x05);

    private final byte type;

    NdpOptionType(byte type) {
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public static NdpOptionType getNdpOptionType(byte type) {
        for (NdpOptionType identifier : NdpOptionType.values()) {
            if (identifier.getType() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown NDP Option type " + type);
    }
}
