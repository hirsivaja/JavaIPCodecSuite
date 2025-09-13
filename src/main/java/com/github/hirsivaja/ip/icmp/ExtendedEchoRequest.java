package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record ExtendedEchoRequest(
        short identifier,
        byte sequenceNumber,
        boolean isLocal,
        ByteArray extension) implements IcmpMessage {

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
        return BASE_LEN + 4 + extension.array().length;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        short identifier = in.getShort();
        byte sequenceNumber = in.get();
        boolean local = (in.get() & 0x01) == 1;
        byte[] extension = new byte[in.remaining()];
        in.get(extension);
        return new ExtendedEchoRequest(identifier, sequenceNumber, local, extension);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.EXTENDED_ECHO_REQUEST;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.EXTENDED_ECHO_REQUEST;
    }

    public byte[] rawExtension() {
        return extension.array();
    }
}
