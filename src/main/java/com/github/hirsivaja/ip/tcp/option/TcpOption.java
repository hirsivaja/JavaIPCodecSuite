package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;

public interface TcpOption {

    void encode(ByteBuffer out);

    int length();

    TcpOptionType optionType();

    static TcpOption decode(ByteBuffer in) {
        TcpOptionType optionType = TcpOptionType.fromType(in.get());
        if(optionType == TcpOptionType.END_OF_OPTIONS_LIST) {
            return Eool.decode();
        }
        if(optionType == TcpOptionType.NO_OPERATION) {
            return Nop.decode();
        }
        int optionLength = Byte.toUnsignedInt(in.get()) - 2;
        byte[] optionBytes = new byte[optionLength];
        in.get(optionBytes);
        ByteBuffer optionBuffer = ByteBuffer.wrap(optionBytes);
        return switch (optionType) {
            case MAXIMUM_SEGMENT_SIZE -> MaximumSegmentSize.decode(optionBuffer);
            case WINDOW_SCALE -> WindowScale.decode(optionBuffer);
            case SACK_PERMITTED -> SackPermitted.decode();
            case SACK -> Sack.decode(optionBuffer);
            case TIMESTAMPS -> Timestamps.decode(optionBuffer);
            case QUICK_START_RESPONSE -> QuickStart.decode(optionBuffer);
            case USER_TIMEOUT -> UserTimeout.decode(optionBuffer);
            case TCP_AUTHENTICATION -> TcpAuthentication.decode(optionBuffer);
            case MULTIPATH_TCP -> MultipathTcp.decode(optionBuffer);
            case TCP_FAST_OPEN_COOKIE -> TcpFastOpen.decode(optionBuffer);
            case ENCRYPTION_NEGOTIATION -> EncryptionNegotiation.decode(optionBuffer);
            default -> GenericTcpOption.decode(optionBuffer, optionType);
        };
    }
}
