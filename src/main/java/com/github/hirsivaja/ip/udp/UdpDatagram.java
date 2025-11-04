package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record UdpDatagram(UdpHeader udpHeader, ByteArray data) implements Ipv4Payload, Ipv6Payload {

    public UdpDatagram(UdpHeader udpHeader, byte[] data) {
        this(udpHeader, new ByteArray(data));
    }

    public UdpDatagram(UdpHeader udpHeader, byte[] data, IpHeader header) {
        this(
                new UdpHeader(udpHeader.srcPort(), udpHeader.dstPort(), udpHeader.len(),
                        calculateChecksum(udpHeader, data, header)),
                new ByteArray(data)
        );
    }

    public UdpDatagram(short srcPort, short dstPort, byte[] data, IpHeader header) {
        this(
                new UdpHeader(srcPort, dstPort, (short) (data.length + UdpHeader.UDP_HEADER_LEN),
                        calculateChecksum(srcPort, dstPort, data, header)),
                new ByteArray(data)
        );
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

    private static byte[] generateChecksumData(IpHeader header, UdpDatagram datagram) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength() + datagram.length());
        checksumBuf.put(header.generatePseudoHeader());
        datagram.udpHeader().encode(checksumBuf);
        checksumBuf.put(datagram.rawData());
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    public static short calculateChecksum(UdpHeader udpHeader, byte[] data, IpHeader header) {
        return calculateChecksum(udpHeader.srcPort(), udpHeader.dstPort(), data, header);
    }

    public static short calculateChecksum(short srcPort, short dstPort, byte[] data, IpHeader header) {
        short len = (short) (data.length + UdpHeader.UDP_HEADER_LEN);
        UdpDatagram datagram = new UdpDatagram(new UdpHeader(srcPort, dstPort, len), data);
        return IpUtils.calculateInternetChecksum(generateChecksumData(header, datagram));
    }

    public static UdpDatagram decode(ByteBuffer in, boolean ensureChecksum, IpHeader ipHeader) {
        UdpHeader udpHeader = UdpHeader.decode(in);
        byte[] data = new byte[udpHeader.dataLength() - UdpHeader.UDP_HEADER_LEN];
        in.get(data);
        UdpDatagram datagram = new UdpDatagram(udpHeader, data);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(ipHeader, datagram));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(ipHeader, datagram));
        }
        return datagram;
    }

    public byte[] rawData() {
        return data.array();
    }
}
