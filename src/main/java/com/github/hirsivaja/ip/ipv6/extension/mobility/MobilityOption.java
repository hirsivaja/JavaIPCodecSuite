package com.github.hirsivaja.ip.ipv6.extension.mobility;

import java.nio.ByteBuffer;

public interface MobilityOption {

    void encode(ByteBuffer out);

    int length();

    MobilityOptionType optionType();

    static MobilityOption decode(ByteBuffer in) {
        MobilityOptionType optionType = MobilityOptionType.fromType(in.get());
        if(optionType == MobilityOptionType.PAD_1) {
            return Pad1.decode();
        }
        int optionLength = Byte.toUnsignedInt(in.get()) * 8;
        byte[] optionBytes = new byte[optionLength - 2];
        in.get(optionBytes);
        ByteBuffer optionBuffer = ByteBuffer.wrap(optionBytes);
        return switch (optionType) {
            case PAD_N -> PadN.decode(optionBuffer);
            default -> GenericMobilityOption.decode(optionBuffer, optionType);
        };
    }
}
