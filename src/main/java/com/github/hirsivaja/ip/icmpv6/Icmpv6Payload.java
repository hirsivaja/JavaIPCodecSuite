package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record Icmpv6Payload(Icmpv6Header header, Icmpv6Message message) implements Ipv6Payload {
    public Icmpv6Payload(Ipv6Header header, Icmpv6Message message) {
        this(new Icmpv6Header(message.type(), message.code(), calculateChecksum(header, message)), message);
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        message.encode(out);
    }

    private static byte[] generateChecksumData(IpHeader header, Icmpv6Payload payload) {
        if(header instanceof Ipv6Header) {
            ByteBuffer checksumBuf = ByteBuffer.allocate(Ipv6Header.HEADER_LEN + payload.length());
            checksumBuf.put(header.generatePseudoHeader());
            checksumBuf.put(payload.header.type().type());
            checksumBuf.put(payload.header.code().code());
            checksumBuf.putShort(payload.header.checksum());
            payload.message.encode(checksumBuf);
            byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
            checksumBuf.get(checksumData);
            return checksumData;
        } else {
            throw new IllegalArgumentException();
        }
    }

    @Override
    public int length() {
        return header.length() + message.length();
    }

    public static short calculateChecksum(Ipv6Header header, Icmpv6Message message) {
        Icmpv6Payload icmpv6Payload = new Icmpv6Payload(new Icmpv6Header(message.type(), message.code(), (short) 0), message);
        return IpUtils.calculateInternetChecksum(generateChecksumData(header, icmpv6Payload));
    }

    public static Icmpv6Payload decode(ByteBuffer in, boolean ensureChecksum, IpHeader ipHeader) {
        Icmpv6Header header = Icmpv6Header.decode(in);
        Icmpv6Message message = Icmpv6Message.decode(in, header.type(), header.code());
        Icmpv6Payload payload = new Icmpv6Payload(header, message);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(ipHeader, payload));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(ipHeader, payload));
        }
        return payload;
    }
}
