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
        out.putShort(IpUtils.calculateInternetChecksum(getChecksumData(header, message)));
        message.encode(out);
    }

    private static byte[] getChecksumData(Ipv6Header header, Icmpv6Message message) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(Ipv6Header.HEADER_LEN + message.getLength());
        checksumBuf.put(header.getPseudoHeader());
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

    public static Ipv6Payload decode(ByteBuffer in, Ipv6Header header) {
        Icmpv6Type type = Icmpv6Type.getType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        Icmpv6Message message = Icmpv6Message.decode(in, type, code);
        IpUtils.ensureInternetChecksum(getChecksumData(header, message), checksum);
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
