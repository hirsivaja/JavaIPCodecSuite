package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;

public record MaximumSegmentSize(short maximumSegmentSize) implements TcpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.putShort(maximumSegmentSize);
    }

    @Override
    public int length() {
        return 4;
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.MAXIMUM_SEGMENT_SIZE;
    }

    public static MaximumSegmentSize decode(ByteBuffer in){
        short maximumSegmentSize = in.getShort();
        return new MaximumSegmentSize(maximumSegmentSize);
    }
}
