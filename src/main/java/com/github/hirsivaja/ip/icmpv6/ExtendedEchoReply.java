package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;

public record ExtendedEchoReply(
        Icmpv6Code code,
        short identifier,
        byte sequenceNumber,
        byte state,
        boolean isActive,
        boolean hasIpv4,
        boolean hasIpv6) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        byte b = 0;
        b = (byte) (((state << 5) | b) & 0xFF);
        if(isActive) {
            b = (byte) ((0x04 | b) & 0xFF);
        }
        if(hasIpv4) {
            b = (byte) ((0x02 | b) & 0xFF);
        }
        if(hasIpv6) {
            b = (byte) ((0x01 | b) & 0xFF);
        }
        out.putShort(identifier);
        out.put(sequenceNumber);
        out.put(b);
    }

    @Override
    public int length() {
        return BASE_LEN + 4;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        short identifier = in.getShort();
        byte sequenceNumber = in.get();
        byte b = in.get();
        byte state = (byte) (((b >> 5) & 0b111) & 0xFF);
        boolean isActive = (b & 0x04) == 4;
        boolean hasIpv4 = (b & 0x02) == 2;
        boolean hasIpv6 = (b & 0x01) == 1;
        return new ExtendedEchoReply(code, identifier, sequenceNumber, state, isActive, hasIpv4, hasIpv6);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.EXTENDED_ECHO_REPLY;
    }
}
