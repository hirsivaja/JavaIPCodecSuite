package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public class EchoRequest implements IcmpMessage {
    private final short identifier;
    private final short sequenceNumber;
    private final byte[] payload;

    public EchoRequest(short identifier, short sequenceNumber, byte[] payload) {
        this.identifier = identifier;
        this.sequenceNumber = sequenceNumber;
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        out.putShort(sequenceNumber);
        out.put(payload);
    }

    @Override
    public int getLength() {
        return 4 + payload.length;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        short identifier = in.getShort();
        short sequenceNumber = in.getShort();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new EchoRequest(identifier, sequenceNumber, payload);
    }

    @Override
    public IcmpType getType() {
        return IcmpType.ECHO_REQUEST;
    }

    @Override
    public byte getCode() {
        return 0;
    }

    public short getIdentifier() {
        return identifier;
    }

    public short getSequenceNumber() {
        return sequenceNumber;
    }

    public byte[] getPayload() {
        return payload;
    }
}
