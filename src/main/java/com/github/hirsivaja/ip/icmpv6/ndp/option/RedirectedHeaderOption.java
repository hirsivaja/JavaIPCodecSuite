package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public class RedirectedHeaderOption implements NdpOption {
    private final byte[] headerAndData;

    public RedirectedHeaderOption(byte[] headerAndData) {
        this.headerAndData = headerAndData;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) ((headerAndData.length + 8) / 8));
        out.putShort((short) 0);
        out.putInt(0);
        out.put(headerAndData);
    }

    @Override
    public int getLength() {
        return headerAndData.length + 8;
    }

    @Override
    public NdpOptionType getOptionType() {
        return NdpOptionType.REDIRECTED_HEADER;
    }

    public static RedirectedHeaderOption decode(ByteBuffer in){
        byte len = in.get();
        in.getShort(); // RESERVED
        in.getInt(); // RESERVED
        byte[] headerAndData = new byte[len * 8 - 8];
        in.get(headerAndData);
        return new RedirectedHeaderOption(headerAndData);
    }

    public byte[] getHeaderAndData() {
        return headerAndData;
    }
}
