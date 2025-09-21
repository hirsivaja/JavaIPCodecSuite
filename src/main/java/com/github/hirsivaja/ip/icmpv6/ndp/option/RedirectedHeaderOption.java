package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record RedirectedHeaderOption(ByteArray headerAndData) implements NdpOption {

    public RedirectedHeaderOption(byte[] headerAndData) {
        this(new ByteArray(headerAndData));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0);
        out.putInt(0);
        out.put(headerAndData.array());
    }

    @Override
    public int length() {
        return headerAndData.length() + 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.REDIRECTED_HEADER;
    }

    public static RedirectedHeaderOption decode(ByteBuffer in){
        in.getShort(); // RESERVED
        in.getInt(); // RESERVED
        byte[] headerAndData = new byte[in.remaining()];
        in.get(headerAndData);
        return new RedirectedHeaderOption(headerAndData);
    }

    public byte[] rawHeaderAndData() {
        return headerAndData.array();
    }
}
