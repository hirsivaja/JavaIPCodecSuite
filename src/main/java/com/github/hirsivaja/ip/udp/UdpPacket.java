package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Packet;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;

import java.nio.ByteBuffer;

public record UdpPacket(IpHeader header, UdpDatagram datagram) implements Ipv4Packet, Ipv6Packet {

    public UdpPacket(IpHeader header, UdpDatagram datagram) {
        this.header = header;
        UdpHeader udpHeader = datagram.udpHeader();
        short checksum = udpHeader.checksum() == 0 ?
                IpUtils.calculateInternetChecksum(generateChecksumData(header, datagram)) :
                udpHeader.checksum();
        this.datagram = new UdpDatagram(
                new UdpHeader(udpHeader.srcPort(), udpHeader.dstPort(), (short) udpHeader.dataLength(), checksum),
                datagram.data()
        );
    }

    public UdpPacket(IpHeader header, UdpHeader udpHeader, byte[] data) {
        this(header, new UdpDatagram(udpHeader, data));
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        datagram.encode(out);
    }

    @Override
    public int length() {
        return header.length() + datagram().length();
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

    public static IpPacket decode(ByteBuffer in, IpHeader header) {
        return decode(in, header, true);
    }

    public static IpPacket decode(ByteBuffer in, IpHeader header, boolean ensureChecksum) {
        UdpDatagram datagram = UdpDatagram.decode(in);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(header, datagram));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(header, datagram));
        }
        return new UdpPacket(header, datagram);
    }

    public UdpHeader udpHeader() {
        return datagram.udpHeader();
    }

    public byte[] rawData() {
        return datagram.rawData();
    }
}
