package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayloadType;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public class Icmpv6Payload implements Ipv6Payload {
    private final Ipv6Header header;
    private final Icmpv6Message message;

    public Icmpv6Payload(Ipv6Header header, Icmpv6Message message){
        this.header = header;
        this.message = message;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.put(message.getType().getType());
        out.put(message.getCode());
        out.putShort(IpUtils.calculateInternetChecksum(getChecksumData(header, message, (short) 0)));
        message.encode(out);
    }

    /**
     * Constructs the data for ICMPv6 checksum calculation as specified in RFC 4443.
     * 
     * <p>ICMPv6 checksum is calculated over the concatenation of:</p>
     * <ol>
     *   <li><b>IPv6 Pseudo-header</b> - 40 bytes, provides protection against misrouted packets
     *       <ul>
     *         <li>Source Address (16 bytes)</li>
     *         <li>Destination Address (16 bytes)</li>
     *         <li>ICMPv6 Length (4 bytes)</li>
     *         <li>Zero padding (3 bytes)</li>
     *         <li>Next Header = 58 (ICMPv6) (1 byte)</li>
     *       </ul>
     *   </li>
     *   <li><b>ICMPv6 Type</b> - 1 byte</li>
     *   <li><b>ICMPv6 Code</b> - 1 byte</li>
     *   <li><b>ICMPv6 Checksum</b> - 2 bytes (set to zero during calculation)</li>
     *   <li><b>ICMPv6 Message Data</b> - Variable length, depends on ICMPv6 type</li>
     * </ol>
     * 
     * <p><b>Important:</b> Unlike ICMP, ICMPv6 requires a pseudo-header for checksum calculation.
     * The checksum is mandatory for all ICMPv6 messages.</p>
     * 
     * @param header the IPv6 header providing the pseudo-header
     * @param message the ICMPv6 message containing type, code, and data
     * @param checksum the checksum value (typically 0 for calculation, actual value for verification)
     * @return byte array containing pseudo-header + ICMPv6 type + code + checksum + message data
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4443">RFC 4443</a>
     */
    private static byte[] getChecksumData(Ipv6Header header, Icmpv6Message message, short checksum) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(Ipv6Header.HEADER_LEN + message.getLength());
        checksumBuf.put(header.getPseudoHeader());
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

    public static Ipv6Payload decode(ByteBuffer in, Ipv6Header header) {
        Icmpv6Type type = Icmpv6Type.getType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        Icmpv6Message message = Icmpv6Message.decode(in, type, code);
        IpUtils.ensureInternetChecksum(getChecksumData(header, message, checksum));
        return new Icmpv6Payload(header, message);
    }

    public Icmpv6Message getMessage() {
        return message;
    }

    @Override
    public String toString(){
        if(message.getType() == Icmpv6Type.RPL) {
            return "ICMPv6 payload " + message.getType() + " with " + RplPayloadType.getRplPayloadType(message.getCode());
        } else {
            return "ICMPv6 payload " + message.getType() + " with code " + message.getCode();
        }
    }

    @Override
    public IpHeader getHeader() {
        return getIpv6Header();
    }

    public Ipv6Header getIpv6Header() {
        return header;
    }
}
