package com.github.hirsivaja.ip.icmpv6.rpl.security;

public enum RplSecurityLevel {
    MAC_32((byte) 0x00, false, false),
    ENC_MAC_32((byte) 0x01, true, false),
    MAC_64((byte) 0x02, false, false),
    ENC_MAC_64((byte) 0x03, true, false),
    SIGN_3072((byte) 0x00, false, true),
    ENC_SIGN_3072((byte) 0x01, true, true),
    SIGN_2048((byte) 0x02, false, true),
    ENC_SIGN_2048((byte) 0x03, true, true);

    private final byte type;
    private final boolean encrypted;
    private final boolean signature;

    RplSecurityLevel(byte type, boolean encrypted, boolean signature) {
        this.type = type;
        this.encrypted = encrypted;
        this.signature = signature;
    }

    public byte getType() {
        return type;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public boolean isSignature() {
        return signature;
    }

    public static RplSecurityLevel getRplSecurityMode(byte type, boolean signature) {
        for (RplSecurityLevel identifier : RplSecurityLevel.values()) {
            if (identifier.getType() == type && identifier.isSignature() == signature) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown RPL Security Level " + type);
    }
}
