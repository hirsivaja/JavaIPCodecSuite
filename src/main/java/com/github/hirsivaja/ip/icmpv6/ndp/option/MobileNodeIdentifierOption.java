package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record MobileNodeIdentifierOption(byte optionCode, ByteArray mobileNodeId) implements NdpOption {

    public MobileNodeIdentifierOption(byte optionCode, byte[] mobileNodeId) {
        this(optionCode, new ByteArray(mobileNodeId));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(optionCode);
        out.put((byte) mobileNodeId.length());
        out.put(mobileNodeId.array());
        out.put(new byte[paddingLen()]);
    }

    @Override
    public int length() {
        return 4 + mobileNodeId.length() + paddingLen();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.MOBILE_NODE_IDENTIFIER;
    }

    public static MobileNodeIdentifierOption decode(ByteBuffer in){
        byte optionCode = in.get();
        int modileNodeIdLength = Byte.toUnsignedInt(in.get());
        byte[] mobileNodeId = new byte[modileNodeIdLength];
        in.get(mobileNodeId);
        byte[] padding = new byte[in.remaining()];
        in.get(padding);
        return new MobileNodeIdentifierOption(optionCode, mobileNodeId);
    }

    private byte paddingLen() {
        return (byte) (8 - ((4 + mobileNodeId.length()) % 8));
    }
}
