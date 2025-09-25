package com.github.hirsivaja.ip.ipv4.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record GenericIpOption(IpOptionType optionType, ByteArray data) implements IpOption {

    public GenericIpOption(IpOptionType optionType, byte[] data) {
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

    public static GenericIpOption decode(ByteBuffer in, IpOptionType optionType){
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new GenericIpOption(optionType, data);
    }
}
