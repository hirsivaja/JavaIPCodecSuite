package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public interface IcmpMessage {
    int BASE_LEN = 4;

    IcmpType type();
    byte code();
    void encode(ByteBuffer out);
    int length();

    static IcmpMessage decode(ByteBuffer in, IcmpType type, byte code) {
        return switch (type) {
            case ECHO_REPLY -> EchoReply.decode(in);
            case DESTINATION_UNREACHABLE -> DestinationUnreachable.decode(in, code);
            case ECHO_REQUEST -> EchoRequest.decode(in);
            default -> GenericIcmpMessage.decode(in, type, code);
        };
    }
}
