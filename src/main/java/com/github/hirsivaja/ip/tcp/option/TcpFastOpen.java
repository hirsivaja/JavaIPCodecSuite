package com.github.hirsivaja.ip.tcp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record TcpFastOpen(ByteArray cookie) implements TcpOption {

    public TcpFastOpen(byte[] cookie) {
        this(new ByteArray(cookie));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(cookie.array());
    }

    @Override
    public int length() {
        return 2 + cookie.length();
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.TCP_FAST_OPEN_COOKIE;
    }

    public static TcpFastOpen decode(ByteBuffer in){
        byte[] cookie = new byte[in.remaining()];
        in.get(cookie);
        return new TcpFastOpen(cookie);
    }
}
