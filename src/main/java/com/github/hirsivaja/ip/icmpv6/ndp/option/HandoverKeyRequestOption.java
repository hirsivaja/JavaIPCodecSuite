package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record HandoverKeyRequestOption(byte algorithmType, ByteArray handoverKeyEncryptionPublicKey) implements NdpOption {

    public HandoverKeyRequestOption(byte algorithmType, byte[] handoverKeyEncryptionPublicKey) {
        this(algorithmType, new ByteArray(handoverKeyEncryptionPublicKey));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(paddingLen());
        out.put((byte) ((algorithmType << 4) & 0xFF));
        out.put(handoverKeyEncryptionPublicKey.array());
    }

    @Override
    public int length() {
        return 4 + handoverKeyEncryptionPublicKey.length() + paddingLen();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.HANDOVER_KEY_REQUEST;
    }

    public static HandoverKeyRequestOption decode(ByteBuffer in){
        int paddingLen = Byte.toUnsignedInt(in.get());
        byte algorithmType = (byte) ((in.get() >> 4) & 0x0F);
        byte[] handoverKeyEncryptionPublicKey = new byte[in.remaining() - paddingLen];
        in.get(handoverKeyEncryptionPublicKey);
        byte[] padding = new byte[paddingLen];
        in.get(padding);
        return new HandoverKeyRequestOption(algorithmType, handoverKeyEncryptionPublicKey);
    }

    private byte paddingLen() {
        return (byte) (8 - (handoverKeyEncryptionPublicKey.length() + 4) % 8);
    }
}
