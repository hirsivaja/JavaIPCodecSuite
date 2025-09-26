package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;

public record Timestamps(int timestampValue, int timestampEchoReply) implements TcpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.putInt(timestampValue);
        out.putInt(timestampEchoReply);
    }

    @Override
    public int length() {
        return 10;
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.TIMESTAMPS;
    }

    public static Timestamps decode(ByteBuffer in){
        int timestampValue = in.getInt();
        int timestampEchoReply = in.getInt();
        return new Timestamps(timestampValue, timestampEchoReply);
    }
}
