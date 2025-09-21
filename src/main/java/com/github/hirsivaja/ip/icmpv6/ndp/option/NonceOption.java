package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record NonceOption(ByteArray nonce) implements NdpOption {

    public NonceOption(byte[] nonce) {
        this(new ByteArray(nonce));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(nonce.array());
    }

    @Override
    public int length() {
        return nonce.length() + 2;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.NONCE;
    }

    public static NonceOption decode(ByteBuffer in){
        byte[] nonce = new byte[in.remaining()];
        in.get(nonce);
        return new NonceOption(nonce);
    }
}
