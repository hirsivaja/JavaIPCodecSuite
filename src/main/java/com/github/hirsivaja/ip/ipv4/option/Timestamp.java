package com.github.hirsivaja.ip.ipv4.option;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record Timestamp(byte pointer, byte flags, List<Integer> ipOrTimestamp) implements IpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(pointer);
        out.put(flags);
        ipOrTimestamp.forEach(out::putInt);
    }

    @Override
    public int length() {
        return 4 + ipOrTimestamp.size() * 4;
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.TIME_STAMP;
    }

    public static Timestamp decode(ByteBuffer in){
        byte pointer = in.get();
        byte flags = in.get();
        List<Integer> ipOrTimestamp = new ArrayList<>();
        while(in.hasRemaining()) {
            ipOrTimestamp.add(in.getInt());
        }
        return new Timestamp(pointer, flags, ipOrTimestamp);
    }
}
