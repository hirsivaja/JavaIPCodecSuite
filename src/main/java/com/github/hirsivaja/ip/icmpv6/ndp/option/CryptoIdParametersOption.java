package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record CryptoIdParametersOption(byte cryptoType, byte modifier, byte earoLength, ByteArray publicKey) implements NdpOption {

    public CryptoIdParametersOption(byte cryptoType, byte modifier, byte earoLength, byte[] publicKey) {
        this(cryptoType, modifier, earoLength, new ByteArray(publicKey));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) publicKey.length());
        out.put(cryptoType);
        out.put(modifier);
        out.put(earoLength);
        out.put(publicKey.array());
        out.put(new byte[paddingLen()]);
    }

    @Override
    public int length() {
        return 7 + publicKey.length() + paddingLen();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.CRYPTO_ID_PARAMETERS;
    }

    public static CryptoIdParametersOption decode(ByteBuffer in){
        short publicKeyLength = (short) (in.getShort() & 0x07FF);
        byte cryptoType = in.get();
        byte modifier = in.get();
        byte earoLength = in.get();
        byte[] publicKey = new byte[publicKeyLength];
        in.get(publicKey);
        byte[] padding = new byte[in.remaining()];
        in.get(padding);
        return new CryptoIdParametersOption(cryptoType, modifier, earoLength, publicKey);
    }

    private byte paddingLen() {
        return (byte) (8 - (7 + publicKey.length()) % 8);
    }
}
