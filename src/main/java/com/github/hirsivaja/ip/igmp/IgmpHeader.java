package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public record IgmpHeader(IgmpType type, byte code, short checksum) {
    public static final int HEADER_LEN = 4;

    public void encode(ByteBuffer out) {
        out.put(type.type());
        out.put(code);
        out.putShort(checksum);
    }

    public static IgmpHeader decode(ByteBuffer in) {
        IgmpType type = IgmpType.fromType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        return new IgmpHeader(type, code, checksum);
    }

    public int length() {
        return HEADER_LEN;
    }
}
