package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public interface IcmpMessage {

    IcmpType getType();
    byte getCode();
    void encode(ByteBuffer out);
    int getLength();

    static IcmpMessage decode(ByteBuffer in, IcmpType type, byte code) {
        switch (type) {
            case ECHO_REPLY: return EchoReply.decode(in);
            case DESTINATION_UNREACHABLE: return DestinationUnreachable.decode(in, code);
            case ECHO_REQUEST: return EchoRequest.decode(in);
            default: return GenericIcmpMessage.decode(in, type, code);
        }
    }
}
