package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Packet;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;

import java.nio.ByteBuffer;

public record TcpPacket(IpHeader header, TcpSegment segment) implements Ipv4Packet, Ipv6Packet {

    public TcpPacket(IpHeader header, TcpHeader tcpHeader, byte[] data) {
        this(header, new TcpSegment(tcpHeader, data));
    }

    public TcpPacket(IpHeader header, TcpSegment segment) {
        this.header = header;
        TcpHeader tcpHeader = segment.tcpHeader();
        short checksum = tcpHeader.checksum() == 0 ?
                IpUtils.calculateInternetChecksum(generateChecksumData(header, segment)) :
                tcpHeader.checksum();
        this.segment = new TcpSegment(new TcpHeader(tcpHeader.srcPort(), tcpHeader.dstPort(), tcpHeader.sequenceNumber(),
                tcpHeader.ackNumber(), tcpHeader.flags(), tcpHeader.windowSize(), checksum,
                tcpHeader.urgentPointer(), tcpHeader.options()), segment.data());
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        segment.encode(out);
    }

    @Override
    public int length() {
        return header.length() + segment.length();
    }

    private static byte[] generateChecksumData(IpHeader header, TcpSegment segment) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength() + segment.length());
        checksumBuf.put(header.generatePseudoHeader());
        segment.tcpHeader().encode(checksumBuf);
        checksumBuf.put(segment.rawPayload());
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    public static IpPacket decode(ByteBuffer in, IpHeader header) {
        return decode(in, header, true);
    }

    public static IpPacket decode(ByteBuffer in, IpHeader header, boolean ensureChecksum) {
        TcpSegment segment = TcpSegment.decode(in);
        byte[] data = new byte[in.remaining()];
        in.get(data);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(header, segment));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(header, segment));
        }
        return new TcpPacket(header, segment);
    }

    public TcpHeader tcpHeader() {
        return segment.tcpHeader();
    }

    public byte[] rawData() {
        return segment.rawPayload();
    }
}
