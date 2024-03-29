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
