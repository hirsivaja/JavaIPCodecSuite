package com.github.hirsivaja.ip.ipv6.extension.mobility;

import java.nio.ByteBuffer;

public record NonceIndices(short homeNonceIndex, short careOfNonceIndex) implements MobilityOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.putShort(homeNonceIndex);
        out.putShort(careOfNonceIndex);
    }

    @Override
    public int length() {
        return 6;
    }

    @Override
    public MobilityOptionType optionType() {
        return MobilityOptionType.NONCE_INDICES;
    }

    public static MobilityOption decode(ByteBuffer in) {
        short homeNonceIndex = in.getShort();
        short careOfNonceIndex = in.getShort();
        return new NonceIndices(homeNonceIndex, careOfNonceIndex);
    }
}
