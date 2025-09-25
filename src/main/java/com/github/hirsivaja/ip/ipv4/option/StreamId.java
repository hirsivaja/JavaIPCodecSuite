package com.github.hirsivaja.ip.ipv4.option;

import java.nio.ByteBuffer;

public record StreamId(short streamId) implements IpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.putShort(streamId);
    }

    @Override
    public int length() {
        return 4;
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.STREAM_ID;
    }

    public static StreamId decode(ByteBuffer in){
        short streamId = in.getShort();
        return new StreamId(streamId);
    }
}
