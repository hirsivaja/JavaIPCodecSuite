package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;

public record SackPermitted() implements TcpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
    }

    @Override
    public int length() {
        return 2;
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.SACK_PERMITTED;
    }

    public static SackPermitted decode(ByteBuffer in){
        return new SackPermitted();
    }
}
