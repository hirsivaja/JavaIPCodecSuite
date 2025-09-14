package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record TrustAnchorOption(byte nameType, ByteArray name) implements NdpOption {

    public TrustAnchorOption(byte nameType, byte[] name) {
        this(nameType, new ByteArray(name));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(nameType);
        out.put((byte) paddingLength());
        out.put(name.array());
        out.put(new byte[paddingLength()]);
    }

    @Override
    public int length() {
        int length = 4 + name.length();
        return length + paddingLength();
    }

    private int paddingLength() {
        int dataLength = 4 + name.length();
        return 8 - (dataLength % 8);
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.TRUST_ANCHOR;
    }

    public static TrustAnchorOption decode(ByteBuffer in){
        int length = in.get() * 8;
        byte nameType = in.get();
        int paddingLength = Byte.toUnsignedInt(in.get());
        in.get(); // RESERVED
        byte[] name = new byte[length - 4 - paddingLength];
        in.get(name);
        byte[] padding = new byte[paddingLength];
        in.get(padding);
        return new TrustAnchorOption(nameType, name);
    }
}
