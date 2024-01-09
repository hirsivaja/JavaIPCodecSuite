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
        out.putShort(IpUtils.calculateInternetChecksum(getChecksumData(message)));
        message.encode(out);
    }

    private static byte[] getChecksumData(IgmpMessage message) {
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
        IgmpType type = IgmpType.getType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        IgmpMessage message = IgmpMessage.decode(in, type, code);
        IpUtils.ensureInternetChecksum(getChecksumData(message), checksum);
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
