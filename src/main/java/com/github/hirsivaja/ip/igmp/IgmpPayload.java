package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;

import java.nio.ByteBuffer;

public class IgmpPayload implements Ipv4Payload {
    private final Ipv4Header header;
    private final IgmpMessage message;

    public IgmpPayload(Ipv4Header header, IgmpMessage message){
        this.header = header;
        this.message = message;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.put(message.getType().getType());
        out.put(message.getCode());
        out.putShort(IpUtils.calculateInternetChecksum(getChecksumData(message, (short) 0)));
        message.encode(out);
    }

    /**
     * Constructs the data for IGMP checksum calculation as specified in RFC 3376.
     * 
     * <p>IGMP checksum is calculated over the entire IGMP message:</p>
     * <ol>
     *   <li><b>IGMP Type</b> - 1 byte (Query, Report, etc.)</li>
     *   <li><b>IGMP Code</b> - 1 byte (Max Response Time for queries)</li>
     *   <li><b>IGMP Checksum</b> - 2 bytes (set to zero during calculation)</li>
     *   <li><b>IGMP Message Data</b> - Variable length, depends on IGMP type and version</li>
     * </ol>
     * 
     * <p><b>Important:</b> IGMP does NOT use a pseudo-header. The checksum covers
     * only the IGMP header and data, similar to ICMP. This applies to all IGMP
     * versions (v1, v2, v3).</p>
     * 
     * @param message the IGMP message containing type, code, and data
     * @param checksum the checksum value (typically 0 for calculation, actual value for verification)
     * @return byte array containing IGMP type + code + checksum + message data for checksum calculation
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc3376">RFC 3376</a>
     */
    private static byte[] getChecksumData(IgmpMessage message, short checksum) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(message.getLength());
        checksumBuf.put(message.getType().getType());
        checksumBuf.put(message.getCode());
        checksumBuf.putShort(checksum);
        message.encode(checksumBuf);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    @Override
    public int getLength() {
        return header.getLength() + message.getLength();
    }

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
        IgmpType type = IgmpType.getType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        IgmpMessage message = IgmpMessage.decode(in, type, code);
        IpUtils.ensureInternetChecksum(getChecksumData(message, checksum));
        return new IgmpPayload(header, message);
    }

    public IgmpMessage getMessage() {
        return message;
    }

    @Override
    public String toString(){
        return "IGMP payload " + message.getType() + " with code " + message.getCode();
    }

    @Override
    public IpHeader getHeader() {
        return getIpv4Header();
    }

    public Ipv4Header getIpv4Header() {
        return header;
    }
}
