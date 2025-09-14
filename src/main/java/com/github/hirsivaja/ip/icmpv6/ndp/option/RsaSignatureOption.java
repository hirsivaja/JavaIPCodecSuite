package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record RsaSignatureOption(ByteArray keyHash, ByteArray digitalSignatureAndPadding) implements NdpOption {

    public RsaSignatureOption(byte[] keyHash, byte[] digitalSignatureAndPadding) {
        this(new ByteArray(keyHash), new ByteArray(digitalSignatureAndPadding));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0);
        out.put(keyHash.array());
        out.put(digitalSignatureAndPadding.array());
    }

    @Override
    public int length() {
        return 4 + keyHash.length() + digitalSignatureAndPadding.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.RSA_SIGNATURE;
    }

    public static RsaSignatureOption decode(ByteBuffer in){
        int length = in.get() * 8;
        in.getShort(); // RESERVED
        byte[] keyHash = new byte[16];
        in.get(keyHash);
        byte[] digitalSignatureAndPadding = new byte[length - 20];
        in.get(digitalSignatureAndPadding);
        return new RsaSignatureOption(keyHash, digitalSignatureAndPadding);
    }
}
