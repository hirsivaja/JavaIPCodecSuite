package com.github.hirsivaja.ip;

public enum EcnCodePoint {
    NO_ECN_NO_ECT((byte) 0x00),
    ECN_1_ECT_1((byte) 0x01),
    ECN_0_ECT_0((byte) 0x02),
    CONGESTION_EXPERIENCED((byte) 0x03);

    private final byte type;

    EcnCodePoint(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static EcnCodePoint fromType(byte type) {
        for (EcnCodePoint identifier : EcnCodePoint.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown ECN code point type " + type);
    }
}
