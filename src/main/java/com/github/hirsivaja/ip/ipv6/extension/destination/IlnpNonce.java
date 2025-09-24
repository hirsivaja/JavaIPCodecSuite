package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record IlnpNonce(ByteArray nonce) implements DestinationOption {

    public IlnpNonce(byte[] nonce) {
        this(new ByteArray(nonce));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(nonce.array());
    }

    @Override
    public int length() {
        return 2 + nonce.length();
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.ILNP_NONCE;
    }

    public static DestinationOption decode(ByteBuffer in) {
        byte[] nonce = new byte[in.remaining()];
        in.get(nonce);
        return new IlnpNonce(nonce);
    }
}
