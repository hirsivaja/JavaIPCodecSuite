package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public class UdpMessagePayload implements Ipv4Payload, Ipv6Payload {
    private final IpHeader header;
    private final UdpHeader udpHeader;
    private final byte[] payload;

    public UdpMessagePayload(IpHeader header, UdpHeader udpHeader, byte[] updPayload) {
        this.header = header;
        short checksum = udpHeader.getChecksum() == 0 ?
                IpUtils.calculateInternetChecksum(getChecksumData(header, udpHeader, updPayload)) :
                udpHeader.getChecksum();
        this.udpHeader = new UdpHeader((short) udpHeader.getSrcPort(), (short) udpHeader.getDstPort(),
                (short) udpHeader.getDataLength(), checksum);
        this.payload = updPayload;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.putShort((short) udpHeader.getSrcPort());
        out.putShort((short) udpHeader.getDstPort());
        out.putShort((short) (payload.length + UdpHeader.UDP_HEADER_LEN));
        out.putShort(udpHeader.getChecksum());
        out.put(payload);
    }

    @Override
    public int getLength() {
        return header.getLength() + UdpHeader.UDP_HEADER_LEN + payload.length;
    }

    /**
     * Constructs the data for UDP checksum calculation as specified in RFC 768.
     * 
     * <p>UDP checksum is calculated over the concatenation of:</p>
     * <ol>
     *   <li><b>Pseudo-header</b> - Provides protection against misrouted packets
     *       <ul>
     *         <li>IPv4: Source IP (4) + Dest IP (4) + Zero (1) + Protocol (1) + UDP Length (2) = 12 bytes</li>
     *         <li>IPv6: Source IP (16) + Dest IP (16) + UDP Length (4) + Zero (3) + Protocol (1) = 40 bytes</li>
     *       </ul>
     *   </li>
     *   <li><b>UDP Header</b> - 8 bytes (with checksum field zeroed)</li>
     *   <li><b>UDP Payload</b> - Variable length data</li>
     * </ol>
     * 
     * <p>The checksum field in the UDP header must be set to zero before calling this method.
     * UDP checksum is optional for IPv4 but mandatory for IPv6.</p>
     * 
     * @param header the IP header (IPv4 or IPv6) providing the pseudo-header
     * @param udpHeader the UDP header with checksum field zeroed
     * @param payload the UDP payload data
     * @return byte array containing pseudo-header + UDP header + payload for checksum calculation
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc768">RFC 768</a>
     */
    private static byte[] getChecksumData(IpHeader header, UdpHeader udpHeader, byte[] payload) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(header.getPseudoHeaderLength() + UdpHeader.UDP_HEADER_LEN + payload.length);
        checksumBuf.put(header.getPseudoHeader());
        udpHeader.encode(checksumBuf);
        checksumBuf.put(payload);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header) {
        UdpHeader udpHeader = UdpHeader.decode(in);
        byte[] updPayload = new byte[udpHeader.getDataLength() - UdpHeader.UDP_HEADER_LEN];
        in.get(updPayload);
        IpUtils.ensureInternetChecksum(getChecksumData(header, udpHeader, updPayload));
        return new UdpMessagePayload(header, udpHeader, updPayload);
    }

    @Override
    public String toString(){
        return "UDP payload " + payload.length + "B to port " + (udpHeader.getDstPort() & 0xFFFF);
    }

    @Override
    public IpHeader getHeader() {
        return header;
    }

    public UdpHeader getUdpHeader() {
        return udpHeader;
    }

    public byte[] getPayload() {
        return payload;
    }
}
