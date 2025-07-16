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

    /**
     * Constructs the data for TCP checksum calculation as specified in RFC 9293.
     * 
     * <p>TCP checksum is calculated over the concatenation of:</p>
     * <ol>
     *   <li><b>Pseudo-header</b> - Provides protection against misrouted packets
     *       <ul>
     *         <li>IPv4: Source IP (4) + Dest IP (4) + Zero (1) + Protocol (1) + TCP Length (2) = 12 bytes</li>
     *         <li>IPv6: Source IP (16) + Dest IP (16) + TCP Length (4) + Zero (3) + Protocol (1) = 40 bytes</li>
     *       </ul>
     *   </li>
     *   <li><b>TCP Header</b> - 20 bytes minimum (with checksum field zeroed)</li>
     *   <li><b>TCP Payload</b> - Variable length data</li>
     * </ol>
     * 
     * <p>The checksum field in the TCP header must be set to zero before calling this method.</p>
     * 
     * @param header the IP header (IPv4 or IPv6) providing the pseudo-header
     * @param tcpHeader the TCP header with checksum field zeroed
     * @param payload the TCP payload data
     * @return byte array containing pseudo-header + TCP header + payload for checksum calculation
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9293#section-3.1">RFC 9293 Section 3.1</a>
     */
    private static byte[] getChecksumData(IpHeader header, TcpHeader tcpHeader, byte[] payload) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(header.getPseudoHeaderLength() + TcpHeader.TCP_HEADER_LEN + payload.length);
        checksumBuf.put(header.getPseudoHeader());
        tcpHeader.encode(checksumBuf);
        checksumBuf.put(payload);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header) {
        TcpHeader tcpHeader = TcpHeader.decode(in);
        byte[] tcpPayload = new byte[in.remaining()];
        in.get(tcpPayload);
        IpUtils.ensureInternetChecksum(getChecksumData(header, tcpHeader, tcpPayload));
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
