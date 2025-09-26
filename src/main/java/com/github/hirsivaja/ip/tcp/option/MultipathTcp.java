package com.github.hirsivaja.ip.tcp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record MultipathTcp(ByteArray subtypeData) implements TcpOption {

    public MultipathTcp(byte[] subtypeData) {
        this(new ByteArray(subtypeData));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(subtypeData.array());
    }

    @Override
    public int length() {
        return 2 + subtypeData.length();
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.MULTIPATH_TCP;
    }

    public static MultipathTcp decode(ByteBuffer in){
        byte[] subtypeData = new byte[in.remaining()];
        in.get(subtypeData);
        return new MultipathTcp(subtypeData);
    }
}
