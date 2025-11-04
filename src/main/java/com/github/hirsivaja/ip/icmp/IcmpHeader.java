package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public record IcmpHeader(IcmpType type, IcmpCode code, short checksum) {
    public static final int HEADER_LEN = 4;

    public void encode(ByteBuffer out) {
        out.put(type.type());
        out.put(code.code());
        out.putShort(checksum);
    }

    public static IcmpHeader decode(ByteBuffer in) {
        IcmpType type = IcmpType.fromType(in.get());
        IcmpCode code = IcmpCode.fromType(type, in.get());
        short checksum = in.getShort();
        return new IcmpHeader(type, code, checksum);
    }

    public int length() {
        return HEADER_LEN;
    }
}
