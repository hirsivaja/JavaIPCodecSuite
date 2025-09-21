package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record HandoverKeyReplyOption(byte algorithmType, short keyLifetime, ByteArray handoverKeyEncryptionPublicKey) implements NdpOption {

    public HandoverKeyReplyOption(byte algorithmType, short keyLifetime, byte[] handoverKeyEncryptionPublicKey) {
        this(algorithmType, keyLifetime, new ByteArray(handoverKeyEncryptionPublicKey));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(paddingLen());
        out.put((byte) ((algorithmType << 4) & 0xFF));
        out.putShort(keyLifetime);
        out.put(handoverKeyEncryptionPublicKey.array());
    }

    @Override
    public int length() {
        return 6 + handoverKeyEncryptionPublicKey.length() + paddingLen();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.HANDOVER_KEY_REPLY;
    }

    public static HandoverKeyReplyOption decode(ByteBuffer in){
        int paddingLen = Byte.toUnsignedInt(in.get());
        byte algorithmType = (byte) ((in.get() >> 4) & 0x0F);
        short keyLifetime = in.getShort();
        byte[] handoverKeyEncryptionPublicKey = new byte[in.remaining() - paddingLen];
        in.get(handoverKeyEncryptionPublicKey);
        byte[] padding = new byte[paddingLen];
        in.get(padding);
        return new HandoverKeyReplyOption(algorithmType, keyLifetime, handoverKeyEncryptionPublicKey);
    }

    private byte paddingLen() {
        return (byte) (8 - (handoverKeyEncryptionPublicKey.length() + 6) % 8);
    }
}
