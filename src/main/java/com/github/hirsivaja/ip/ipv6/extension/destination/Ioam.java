package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record Ioam(byte ioamOptionType, ByteArray data) implements DestinationOption {

    public Ioam(byte ioamOptionType, byte[] data) {
        this(ioamOptionType, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put((byte) 0); // RESERVED
        out.put(ioamOptionType);
        out.put(data.array());
    }

    @Override
    public int length() {
        return 4 + data.length();
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.IOAM;
    }

    public static DestinationOption decode(ByteBuffer in) {
        in.get(); // RESERVED
        byte ioamOptionType = in.get();
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new Ioam(ioamOptionType, data);
    }
}
