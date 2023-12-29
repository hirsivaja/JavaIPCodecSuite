package com.github.hirsivaja.ip;

import java.nio.ByteBuffer;

public interface IpHeader {
    void encode(ByteBuffer out);
    byte[] getPseudoHeader();
    int getLength();
    int getPseudoHeaderLength();

    enum EcnCodePoint {
        NO_ECN_NO_ECT((byte) 0x00),
        ECN_1_ECT_1((byte) 0x01),
        ECN_0_ECT_0((byte) 0x02),
        CONGESTION_EXPERIENCED((byte) 0x03);

        private final byte type;

        EcnCodePoint(byte type) {
            this.type = type;
        }

        public byte getType() {
            return type;
        }

        public static EcnCodePoint getType(byte type) {
            for (EcnCodePoint identifier : EcnCodePoint.values()) {
                if (identifier.getType() == type) {
                    return identifier;
                }
            }
            throw new IllegalArgumentException("Unknown ECN code point type " + type);
        }
    }
}
