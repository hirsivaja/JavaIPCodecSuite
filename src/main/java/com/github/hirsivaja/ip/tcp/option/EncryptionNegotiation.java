package com.github.hirsivaja.ip.tcp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record EncryptionNegotiation(ByteArray data) implements TcpOption {

    public EncryptionNegotiation(byte[] data) {
        this(new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(data.array());
    }

    @Override
    public int length() {
        return 2 + data.length();
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.ENCRYPTION_NEGOTIATION;
    }

    public static EncryptionNegotiation decode(ByteBuffer in){
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new EncryptionNegotiation(data);
    }
}
