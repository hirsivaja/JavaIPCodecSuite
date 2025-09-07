package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record Icmpv6Payload(Ipv6Header header, Icmpv6Message message) implements Ipv6Payload {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.put(message.type().type());
        out.put(message.code());
        out.putShort(IpUtils.calculateInternetChecksum(generateChecksumData(header, message, (short) 0)));
        message.encode(out);
    }

    private static byte[] generateChecksumData(Ipv6Header header, Icmpv6Message message, short checksum) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(Ipv6Header.HEADER_LEN + message.length());
        checksumBuf.put(header.generatePseudoHeader());
        checksumBuf.put(message.type().type());
        checksumBuf.put(message.code());
        checksumBuf.putShort(checksum);
        message.encode(checksumBuf);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    @Override
    public int length() {
        return header.length() + message.length();
    }

    public static Ipv6Payload decode(ByteBuffer in, Ipv6Header header) {
        Icmpv6Type type = Icmpv6Type.fromType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        Icmpv6Message message = Icmpv6Message.decode(in, type, code);
        IpUtils.ensureInternetChecksum(generateChecksumData(header, message, checksum));
        return new Icmpv6Payload(header, message);
    }

    public Ipv6Header ipv6Header() {
        return header;
    }
}
