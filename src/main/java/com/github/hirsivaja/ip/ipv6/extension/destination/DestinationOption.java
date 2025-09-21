package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public interface DestinationOption {
    static byte SKIP = 0;
    static byte DISCARD = 1;
    static byte DISCARD_AND_SEND_ERROR = 2;
    static byte DISCARD_AND_SEND_ERROR_IF_NOT_MULTICAST = 3;

    void encode(ByteBuffer out);

    int length();

    DestinationOptionType optionType();

    static DestinationOption decode(ByteBuffer in) {
        DestinationOptionType optionType = DestinationOptionType.fromType(in.get());
        if(optionType == DestinationOptionType.PAD_1) {
            return Pad1.decode();
        }
        int optionLength = Byte.toUnsignedInt(in.get());
        byte[] optionBytes = new byte[optionLength];
        in.get(optionBytes);
        ByteBuffer optionBuffer = ByteBuffer.wrap(optionBytes);
        return switch (optionType) {
            case PAD_N -> PadN.decode(optionBuffer);
            default -> GenericDestinationOption.decode(optionBuffer, optionType);
        };
    }
}
