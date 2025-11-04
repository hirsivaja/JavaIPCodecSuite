package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record TcpSegment(TcpHeader tcpHeader, ByteArray data) implements Ipv4Payload, Ipv6Payload {

    public TcpSegment(TcpHeader tcpHeader, byte[] data) {
        this(tcpHeader, new ByteArray(data));
    }

    public TcpSegment(TcpHeader tcpHeader, byte[] data, IpHeader header) {
        this(tcpHeader.withChecksum(calculateChecksum(tcpHeader, data, header)), new ByteArray(data));
    }

    public void encode(ByteBuffer out) {
        tcpHeader.encode(out);
        out.put(data.array());
    }

    public int length() {
        return TcpHeader.TCP_HEADER_LEN + data.length();
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

    public static short calculateChecksum(TcpHeader tcpHeader, byte[] data, IpHeader header) {
        TcpSegment segment = new TcpSegment(tcpHeader.withChecksum((short) 0), data);
        return IpUtils.calculateInternetChecksum(generateChecksumData(header, segment));
    }

    public static TcpSegment decode(ByteBuffer in, boolean ensureChecksum, IpHeader ipHeader) {
        TcpHeader tcpHeader = TcpHeader.decode(in);
        byte[] data = new byte[in.remaining()];
        in.get(data);
        TcpSegment segment = new TcpSegment(tcpHeader, data);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(ipHeader, segment));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(ipHeader, segment));
        }
        return segment;
    }

    public byte[] rawPayload() {
        return data.array();
    }
}
