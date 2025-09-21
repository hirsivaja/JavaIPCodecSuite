package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record UdpMessagePayload(
        IpHeader header,
        UdpHeader udpHeader,
        ByteArray payload) implements Ipv4Payload, Ipv6Payload {

    public UdpMessagePayload(IpHeader header, UdpHeader udpHeader, byte[] updPayload) {
        this(header, udpHeader, new ByteArray(updPayload));
    }

    public UdpMessagePayload(IpHeader header, UdpHeader udpHeader, ByteArray payload) {
        this.header = header;
        short checksum = udpHeader.checksum() == 0 ?
                IpUtils.calculateInternetChecksum(generateChecksumData(header, udpHeader, payload.array())) :
                udpHeader.checksum();
        this.udpHeader = new UdpHeader(udpHeader.srcPort(), udpHeader.dstPort(),
                (short) udpHeader.dataLength(), checksum);
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.putShort(udpHeader.srcPort());
        out.putShort(udpHeader.dstPort());
        out.putShort((short) (payload.length() + UdpHeader.UDP_HEADER_LEN));
        out.putShort(udpHeader.checksum());
        out.put(payload.array());
    }

    @Override
    public int length() {
        return header.length() + UdpHeader.UDP_HEADER_LEN + payload.length();
    }

    private static byte[] generateChecksumData(IpHeader header, UdpHeader udpHeader, byte[] payload) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength() + UdpHeader.UDP_HEADER_LEN + payload.length);
        checksumBuf.put(header.generatePseudoHeader());
        udpHeader.encode(checksumBuf);
        checksumBuf.put(payload);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header) {
        return decode(in, header, true);
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header, boolean ensureChecksum) {
        UdpHeader udpHeader = UdpHeader.decode(in);
        byte[] updPayload = new byte[udpHeader.dataLength() - UdpHeader.UDP_HEADER_LEN];
        in.get(updPayload);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(header, udpHeader, updPayload));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(header, udpHeader, updPayload));
        }
        return new UdpMessagePayload(header, udpHeader, updPayload);
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
