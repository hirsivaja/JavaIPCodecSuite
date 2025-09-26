package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;

public record WindowScale(byte shiftCount) implements TcpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(shiftCount);
    }

    @Override
    public int length() {
        return 3;
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.WINDOW_SCALE;
    }

    public static WindowScale decode(ByteBuffer in){
        byte shiftCount = in.get();
        return new WindowScale(shiftCount);
    }
}
