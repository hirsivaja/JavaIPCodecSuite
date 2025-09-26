package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record Sack(List<Integer> blocks) implements TcpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        blocks.forEach(out::putInt);
    }

    @Override
    public int length() {
        return 2 + 4 * blocks.size();
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.SACK;
    }

    public static Sack decode(ByteBuffer in){
        List<Integer> blocks = new ArrayList<>();
        for(int i = 0; i < in.remaining() / 4; i++) {
            blocks.add(in.getInt());
        }
        return new Sack(blocks);
    }
}
