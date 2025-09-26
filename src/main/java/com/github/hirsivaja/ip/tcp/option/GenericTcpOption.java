package com.github.hirsivaja.ip.tcp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record GenericTcpOption(TcpOptionType optionType, ByteArray data) implements TcpOption {

    public GenericTcpOption(TcpOptionType optionType, byte[] data) {
        this(optionType, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(data.array());
    }

    @Override
    public int length() {
        return data.length() + 2;
    }

    public static GenericTcpOption decode(ByteBuffer in, TcpOptionType optionType){
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new GenericTcpOption(optionType, data);
    }
}
