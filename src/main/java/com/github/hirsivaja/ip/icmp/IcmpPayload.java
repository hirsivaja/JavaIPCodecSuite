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
        out.putShort(IpUtils.calculateInternetChecksum(getChecksumData(message)));
        message.encode(out);
    }

    private static byte[] getChecksumData(IcmpMessage message) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(message.getLength());
        checksumBuf.put(message.getType().getType());
        checksumBuf.put(message.getCode());
        checksumBuf.putShort((short) 0);
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
        short expectedChecksum = IpUtils.calculateInternetChecksum(getChecksumData(message));
        if(expectedChecksum != checksum){
            throw new IllegalArgumentException("Checksum does not match!");
        }
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
