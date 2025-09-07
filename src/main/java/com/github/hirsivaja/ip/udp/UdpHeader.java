package com.github.hirsivaja.ip.udp;

import java.nio.ByteBuffer;

public record UdpHeader(short srcPort, short dstPort, short len, short checksum) {
    public static final int UDP_HEADER_LEN = 8;

    public UdpHeader(short srcPort, short dstPort, short len) {
        this(srcPort, dstPort, len, (short) 0);
    }

    public void encode(ByteBuffer out) {
        out.putShort(srcPort);
        out.putShort(dstPort);
        out.putShort(len);
        out.putShort(checksum);
    }

    public int length() {
        return UDP_HEADER_LEN;
    }

    public static UdpHeader decode(ByteBuffer in) {
        short srcPort = in.getShort();
        short dstPort = in.getShort();
        short len = in.getShort();
        short checksum = in.getShort();
        return new UdpHeader(srcPort, dstPort, len, checksum);
    }

    public int dataLength() {
        return Short.toUnsignedInt(len);
    }
}
