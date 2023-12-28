package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public class TcpMessagePayload implements Ipv4Payload, Ipv6Payload {
    private final IpHeader header;
    private final TcpHeader tcpHeader;
    private final byte[] payload;

    public TcpMessagePayload(IpHeader header, TcpHeader tcpHeader, byte[] tcpPayload) {
        this.header = header;
        short checksum = tcpHeader.getChecksum() == 0 ?
                IpUtils.calculateInternetChecksum(getChecksumData(header, tcpHeader, tcpPayload)) :
                tcpHeader.getChecksum();
        this.tcpHeader = new TcpHeader((short) tcpHeader.getSrcPort(), (short) tcpHeader.getDstPort(), tcpHeader.getSequenceNumber(),
                tcpHeader.getAckNumber(), tcpHeader.getFlags(), tcpHeader.getWindowSize(), checksum,
                tcpHeader.getUrgentPointer(), tcpHeader.getOptions());
        this.payload = tcpPayload;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        tcpHeader.encode(out);
        out.put(payload);
    }

    @Override
    public int getLength() {
        return header.getLength() + TcpHeader.TCP_HEADER_LEN + payload.length;
    }

    private static byte[] getChecksumData(IpHeader header, TcpHeader tcpHeader, byte[] payload) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(header.getPseudoHeaderLength() + TcpHeader.TCP_HEADER_LEN + payload.length);
        checksumBuf.put(header.getPseudoHeader());
        tcpHeader.encode(checksumBuf, true);
        checksumBuf.put(payload);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header) {
        TcpHeader tcpHeader = TcpHeader.decode(in);
        byte[] tcpPayload = new byte[in.remaining()];
        in.get(tcpPayload);
        short expectedChecksum = IpUtils.calculateInternetChecksum(getChecksumData(header, tcpHeader, tcpPayload));
        if(expectedChecksum != tcpHeader.getChecksum()){
            throw new IllegalArgumentException("Checksum does not match!");
        }
        return new TcpMessagePayload(header, tcpHeader, tcpPayload);
    }

    @Override
    public String toString(){
        return "TCP payload " + payload.length + "B to port " + (tcpHeader.getDstPort() & 0xFFFF);
    }

    @Override
    public IpHeader getHeader() {
        return header;
    }

    public TcpHeader getTcpHeader() {
        return tcpHeader;
    }

    public byte[] getPayload() {
        return payload;
    }
}
