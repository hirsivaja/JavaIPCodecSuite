package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;

public record Icmpv6Header(Icmpv6Type type, Icmpv6Code code, short checksum) {
    public static final int HEADER_LEN = 4;

    public void encode(ByteBuffer out) {
        out.put(type.type());
        out.put(code.code());
        out.putShort(checksum);
    }

    public static Icmpv6Header decode(ByteBuffer in) {
        Icmpv6Type type = Icmpv6Type.fromType(in.get());
        Icmpv6Code code = Icmpv6Code.fromType(type, in.get());
        short checksum = in.getShort();
        return new Icmpv6Header(type, code, checksum);
    }

    public int length() {
        return HEADER_LEN;
    }
}
