package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;

import java.nio.ByteBuffer;

public record IcmpPayload(IcmpHeader header, IcmpMessage message) implements Ipv4Payload {
    public IcmpPayload(IcmpMessage message) {
        this(new IcmpHeader(message.type(), message.code(), calculateChecksum(message)), message);
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        message.encode(out);
    }

    private static byte[] generateChecksumData(IcmpPayload icmpPayload) {
        IcmpHeader header = icmpPayload.header;
        IcmpMessage message = icmpPayload.message;
        ByteBuffer checksumBuf = ByteBuffer.allocate(IcmpHeader.HEADER_LEN + message.length());
        checksumBuf.put(header.type().type());
        checksumBuf.put(header.code().code());
        checksumBuf.putShort(header.checksum());
        message.encode(checksumBuf);
        byte[] checksumData = new byte[checksumBuf.rewind().remaining()];
        checksumBuf.get(checksumData);
        return checksumData;
    }

    @Override
    public int length() {
        return header.length() + message.length();
    }

    public static short calculateChecksum(IcmpMessage message) {
        IcmpHeader header = new IcmpHeader(message.type(), message.code(), (short) 0);
        IcmpPayload icmpPayload = new IcmpPayload(header, message);
        return IpUtils.calculateInternetChecksum(generateChecksumData(icmpPayload));
    }

    public static IcmpPayload decode(ByteBuffer in, boolean ensureChecksum) {
        IcmpHeader header = IcmpHeader.decode(in);
        IcmpMessage message = IcmpMessage.decode(in, header.type(), header.code());
        IcmpPayload payload = new IcmpPayload(header, message);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(payload));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(payload));
        }
        return payload;
    }
}
