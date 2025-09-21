package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record GenericDestinationOption(DestinationOptionType optionType, ByteArray data) implements DestinationOption {

    public GenericDestinationOption(DestinationOptionType optionType, byte[] data) {
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

    public static GenericDestinationOption decode(ByteBuffer in, DestinationOptionType optionType){
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new GenericDestinationOption(optionType, data);
    }
}
