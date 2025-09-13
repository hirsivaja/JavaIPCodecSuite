package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public record Timestamp(
        short identifier,
        short sequenceNumber,
        int originateTimestamp,
        int receiveTimestamp,
        int transmitTimestamp) implements IcmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        out.putShort(sequenceNumber);
        out.putInt(originateTimestamp);
        out.putInt(receiveTimestamp);
        out.putInt(transmitTimestamp);
    }

    @Override
    public int length() {
        return BASE_LEN + 16;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        short identifier = in.getShort();
        short sequenceNumber = in.getShort();
        int originateTimestamp = in.getInt();
        int receiveTimestamp = in.getInt();
        int transmitTimestamp = in.getInt();
        return new Timestamp(identifier, sequenceNumber, originateTimestamp, receiveTimestamp, transmitTimestamp);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.TIMESTAMP;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.TIMESTAMP;
    }
}
