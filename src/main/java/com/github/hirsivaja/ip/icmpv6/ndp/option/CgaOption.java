package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record CgaOption(ByteArray cgaParameters) implements NdpOption {

    public CgaOption(byte[] cgaParameters) {
        this(new ByteArray(cgaParameters));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put((byte) paddingLength());
        out.put((byte) 0);
        out.put(cgaParameters.array());
        out.put(new byte[paddingLength()]);
    }

    @Override
    public int length() {
        int length = 4 + cgaParameters.length();
        return length + paddingLength();
    }

    private int paddingLength() {
        int dataLength = 4 + cgaParameters.length();
        return 8 - (dataLength % 8);
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.CGA;
    }

    public static CgaOption decode(ByteBuffer in){
        int paddingLength = Byte.toUnsignedInt(in.get());
        in.get(); // RESERVED
        byte[] cgaParameters = new byte[in.remaining() - paddingLength];
        in.get(cgaParameters);
        byte[] padding = new byte[paddingLength];
        in.get(padding);
        return new CgaOption(cgaParameters);
    }
}
