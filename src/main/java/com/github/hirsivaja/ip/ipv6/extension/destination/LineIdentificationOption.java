package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record LineIdentificationOption(ByteArray lineId) implements DestinationOption {

    public LineIdentificationOption(byte[] lineId) {
        this(new ByteArray(lineId));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(lineId.array());
    }

    @Override
    public int length() {
        return 2 + lineId.length();
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.LINE_IDENTIFICATION;
    }

    public static DestinationOption decode(ByteBuffer in) {
        int lineIdLen = Byte.toUnsignedInt(in.get());
        byte[] lineId = new byte[lineIdLen];
        in.get(lineId);
        return new LineIdentificationOption(lineId);
    }
}
