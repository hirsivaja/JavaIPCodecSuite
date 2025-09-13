package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public record AddressMaskRequest(short identifier, short sequenceNumber, int addressMask) implements IcmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        out.putShort(sequenceNumber);
        out.putInt(addressMask);
    }

    @Override
    public int length() {
        return BASE_LEN + 8;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        short identifier = in.getShort();
        short sequenceNumber = in.getShort();
        int addressMask = in.getInt();
        return new AddressMaskRequest(identifier, sequenceNumber, addressMask);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.ADDRESS_MASK_REQUEST;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.ADDRESS_MASK_REQUEST;
    }
}
