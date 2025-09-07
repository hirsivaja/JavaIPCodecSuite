package com.github.hirsivaja.ip.icmpv6.rpl.security;

public enum RplSecurityMode {
    GROUP_KEY((byte) 0x00),
    PER_PAIR_KEY((byte) 0x01),
    GROUP_KEY_WITH_SOURCE((byte) 0x02),
    NODE_SIGNATURE_KEY((byte) 0x03);

    private final byte type;

    RplSecurityMode(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static RplSecurityMode fromRplSecurityMode(byte type) {
        for (RplSecurityMode identifier : RplSecurityMode.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown RPL Security Mode " + type);
    }
}
