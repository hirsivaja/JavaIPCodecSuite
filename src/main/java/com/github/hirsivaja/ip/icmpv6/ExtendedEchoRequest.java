package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record ExtendedEchoRequest(
        short identifier,
        byte sequenceNumber,
        boolean isLocal,
        ByteArray extension) implements Icmpv6Message {

    public ExtendedEchoRequest(short identifier, byte sequenceNumber, boolean isLocal, byte[] extension) {
        this(identifier, sequenceNumber, isLocal, new ByteArray(extension));
    }

    @Override
    public void encode(ByteBuffer out) {
        byte local = isLocal ? (byte) 1 : (byte) 0;
        out.putShort(identifier);
        out.put(sequenceNumber);
        out.put(local);
        out.put(extension.array());
    }

    @Override
    public int length() {
        return 4 + extension.array().length;
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        short identifier = in.getShort();
        byte sequenceNumber = in.get();
        boolean local = (in.get() & 0x01) == 1;
        byte[] extension = new byte[in.remaining()];
        in.get(extension);
        return new ExtendedEchoRequest(identifier, sequenceNumber, local, extension);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.EXTENDED_ECHO_REQUEST;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.EXTENDED_ECHO_REQUEST;
    }

    public byte[] rawExtension() {
        return extension.array();
    }
}
