package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record TcpMessagePayload(
        IpHeader header,
        TcpHeader tcpHeader,
        ByteArray payload) implements Ipv4Payload, Ipv6Payload {

    public TcpMessagePayload(IpHeader header, TcpHeader tcpHeader, byte[] tcpPayload) {
        this(header, tcpHeader, new ByteArray(tcpPayload));
    }

    public TcpMessagePayload(IpHeader header, TcpHeader tcpHeader, ByteArray payload) {
        this.header = header;
        short checksum = tcpHeader.checksum() == 0 ?
                IpUtils.calculateInternetChecksum(generateChecksumData(header, tcpHeader, payload.array())) :
                tcpHeader.checksum();
        this.tcpHeader = new TcpHeader(tcpHeader.srcPort(), tcpHeader.dstPort(), tcpHeader.sequenceNumber(),
                tcpHeader.ackNumber(), tcpHeader.flags(), tcpHeader.windowSize(), checksum,
                tcpHeader.urgentPointer(), tcpHeader.rawOptions());
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        tcpHeader.encode(out);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return header.length() + TcpHeader.TCP_HEADER_LEN + payload.length();
    }

    private static byte[] generateChecksumData(IpHeader header, TcpHeader tcpHeader, byte[] payload) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength() + TcpHeader.TCP_HEADER_LEN + payload.length);
        checksumBuf.put(header.generatePseudoHeader());
        tcpHeader.encode(checksumBuf);
        checksumBuf.put(payload);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header) {
        return decode(in, header, true);
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header, boolean ensureChecksum) {
        TcpHeader tcpHeader = TcpHeader.decode(in);
        byte[] tcpPayload = new byte[in.remaining()];
        in.get(tcpPayload);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(header, tcpHeader, tcpPayload));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(header, tcpHeader, tcpPayload));
        }
        return new TcpMessagePayload(header, tcpHeader, tcpPayload);
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
