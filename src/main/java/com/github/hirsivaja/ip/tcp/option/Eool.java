package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;

public record Eool() implements TcpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
    }

    @Override
    public int length() {
        return 1;
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.END_OF_OPTIONS_LIST;
    }

    public static TcpOption decode() {
        return new Eool();
    }
}
