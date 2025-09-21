package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record GenericNdpOption(NdpOptionType optionType, ByteArray data) implements NdpOption {

    public GenericNdpOption(NdpOptionType optionType, byte[] data) {
        this(optionType, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(data.array());
    }

    @Override
    public int length() {
        return data.length() + 2;
    }

    public static GenericNdpOption decode(ByteBuffer in, NdpOptionType optionType){
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new GenericNdpOption(optionType, data);
    }
}
