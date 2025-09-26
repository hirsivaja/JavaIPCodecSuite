package com.github.hirsivaja.ip.tcp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record TcpAuthentication(byte keyId, byte rNextKeyId, ByteArray mac) implements TcpOption {

    public TcpAuthentication(byte keyId, byte rNextKeyId, byte[] mac) {
        this(keyId, rNextKeyId, new ByteArray(mac));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(keyId);
        out.put(rNextKeyId);
        out.put(mac.array());
    }

    @Override
    public int length() {
        return 4 + mac.length();
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.TCP_AUTHENTICATION;
    }

    public static TcpAuthentication decode(ByteBuffer in){
        byte keyId = in.get();
        byte rNextKeyId = in.get();
        byte[] mac = new byte[in.remaining()];
        in.get(mac);
        return new TcpAuthentication(keyId, rNextKeyId, mac);
    }
}
