package com.github.hirsivaja.ip.udp;

import java.nio.ByteBuffer;

public class UdpHeader {
    public static final int UDP_HEADER_LEN = 8;
    private final short srcPort;
    private final short dstPort;
    private final short len;
    private final short checksum;

    public UdpHeader(short srcPort, short dstPort, short len) {
        this(srcPort, dstPort, len, (short) 0);
    }

    public UdpHeader(short srcPort, short dstPort, short len, short checksum) {
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.len = len;
        this.checksum = checksum;
    }

    public void encode(ByteBuffer out) {
        out.putShort(srcPort);
        out.putShort(dstPort);
        out.putShort(len);
        out.putShort(checksum);
    }

    public int getLength() {
        return UDP_HEADER_LEN;
    }

    public static UdpHeader decode(ByteBuffer in) {
        short srcPort = in.getShort();
        short dstPort = in.getShort();
        short len = in.getShort();
        short checksum = in.getShort();
        return new UdpHeader(srcPort, dstPort, len, checksum);
    }

    public int getSrcPort() {
        return Short.toUnsignedInt(srcPort);
    }

    public int getDstPort() {
        return Short.toUnsignedInt(dstPort);
    }

    public int getDataLength() {
        return Short.toUnsignedInt(len);
    }

    public short getChecksum() {
        return checksum;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "(" +
                "srcPort=" + getSrcPort() +
                ", dstPort=" + getDstPort() +
                ", len=" + getDataLength() +
                ", checksum=" + checksum +
                ")";
    }
}
