package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record Calipso(int domainOfInterpretation, byte sensLevel, short checksum, ByteArray compartmentBitmap) implements DestinationOption {

    private Calipso(int domainOfInterpretation, byte sensLevel, short checksum, byte[] compartmentBitmap) {
        this(domainOfInterpretation, sensLevel, checksum, new ByteArray(compartmentBitmap));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.putInt(domainOfInterpretation);
        out.put((byte) (compartmentBitmap.length() / 4));
        out.put(sensLevel);
        out.putShort(checksum);
        out.put(compartmentBitmap.array());
    }

    @Override
    public int length() {
        return 10 + compartmentBitmap.length();
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.CALIPSO;
    }

    public static DestinationOption decode(ByteBuffer in) {
        int domainOfInterpretation = in.getInt();
        int compartmentLen = Byte.toUnsignedInt(in.get()) * 4;
        byte sensLevel = in.get();
        short checksum = in.getShort();
        byte[] compartmentBitmap = new byte[compartmentLen];
        return new Calipso(domainOfInterpretation, sensLevel, checksum, compartmentBitmap);
    }
}
