package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public record InformationReply(short identifier, short sequenceNumber) implements IcmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        out.putShort(sequenceNumber);
    }

    @Override
    public int length() {
        return 4;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        short identifier = in.getShort();
        short sequenceNumber = in.getShort();
        return new InformationReply(identifier, sequenceNumber);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.INFORMATION_REPLY;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.INFORMATION_REPLY;
    }
}
