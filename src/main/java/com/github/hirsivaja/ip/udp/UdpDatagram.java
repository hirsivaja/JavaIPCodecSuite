package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.ByteArray;

import java.nio.ByteBuffer;

public record UdpDatagram(UdpHeader udpHeader, ByteArray data) {

    public UdpDatagram(UdpHeader udpHeader, byte[] data) {
        this(udpHeader, new ByteArray(data));
    }

    public void encode(ByteBuffer out) {
        out.putShort(udpHeader.srcPort());
        out.putShort(udpHeader.dstPort());
        out.putShort((short) (data.length() + UdpHeader.UDP_HEADER_LEN));
        out.putShort(udpHeader.checksum());
        out.put(data.array());
    }

    public int length() {
        return UdpHeader.UDP_HEADER_LEN + data.length();
    }

    public static UdpDatagram decode(ByteBuffer in) {
        UdpHeader udpHeader = UdpHeader.decode(in);
        byte[] data = new byte[udpHeader.dataLength() - UdpHeader.UDP_HEADER_LEN];
        in.get(data);
        return new UdpDatagram(udpHeader, data);
    }

    public byte[] rawData() {
        return data.array();
    }
}
