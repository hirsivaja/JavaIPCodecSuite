package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;

import java.nio.ByteBuffer;

public class IcmpPayload implements Ipv4Payload {
    private final Ipv4Header header;
    private final IcmpMessage message;

    public IcmpPayload(Ipv4Header header, IcmpMessage message){
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
     * Constructs the data for ICMP checksum calculation as specified in RFC 792.
     * 
     * <p>ICMP checksum is calculated over the entire ICMP message:</p>
     * <ol>
     *   <li><b>ICMP Type</b> - 1 byte</li>
     *   <li><b>ICMP Code</b> - 1 byte</li>
     *   <li><b>ICMP Checksum</b> - 2 bytes (set to zero during calculation)</li>
     *   <li><b>ICMP Message Data</b> - Variable length, depends on ICMP type</li>
     * </ol>
     * 
     * <p><b>Important:</b> ICMP does NOT use a pseudo-header. The checksum covers
     * only the ICMP header and data, not any IP header information.</p>
     * 
     * @param message the ICMP message containing type, code, and data
     * @param checksum the checksum value (typically 0 for calculation, actual value for verification)
     * @return byte array containing ICMP type + code + checksum + message data for checksum calculation
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc792">RFC 792</a>
     */
    private static byte[] getChecksumData(IcmpMessage message, short checksum) {
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
        IcmpType type = IcmpType.getType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        IcmpMessage message = IcmpMessage.decode(in, type, code);
        IpUtils.ensureInternetChecksum(getChecksumData(message, checksum));
        return new IcmpPayload(header, message);
    }

    public IcmpMessage getMessage() {
        return message;
    }

    @Override
    public String toString(){
        return "ICMP payload " + message.getType() + " with code " + message.getCode();
    }

    @Override
    public IpHeader getHeader() {
        return getIpv4Header();
    }

    public Ipv4Header getIpv4Header() {
        return header;
    }
}
