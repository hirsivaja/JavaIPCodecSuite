package com.github.hirsivaja.ip.ipv6.extension.mobility;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record GenericMobilityOption(MobilityOptionType optionType, ByteArray data) implements MobilityOption {

    public GenericMobilityOption(MobilityOptionType optionType, byte[] data) {
        this(optionType, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(data.array());
    }

    @Override
    public int length() {
        return data.length() + 2;
    }

    public static GenericMobilityOption decode(ByteBuffer in, MobilityOptionType optionType){
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new GenericMobilityOption(optionType, data);
    }
}
