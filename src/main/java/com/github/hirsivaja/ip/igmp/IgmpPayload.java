package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;

import java.nio.ByteBuffer;

public record IgmpPayload(IgmpHeader header, IgmpMessage message) implements Ipv4Payload {
    public IgmpPayload(IgmpMessage message) {
        this(new IgmpHeader(message.type(), message.code(), calculateChecksum(message)), message);
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        message.encode(out);
    }

    private static byte[] generateChecksumData(IgmpPayload igmpPayload) {
        IgmpHeader header = igmpPayload.header;
        IgmpMessage message = igmpPayload.message;
        ByteBuffer checksumBuf = ByteBuffer.allocate(IgmpHeader.HEADER_LEN + message.length());
        checksumBuf.put(message.type().type());
        checksumBuf.put(message.code());
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

    public static short calculateChecksum(IgmpMessage message) {
        IgmpHeader header = new IgmpHeader(message.type(), message.code(), (short) 0);
        IgmpPayload igmpPayload = new IgmpPayload(header, message);
        return IpUtils.calculateInternetChecksum(generateChecksumData(igmpPayload));
    }

    public static IgmpPayload decode(ByteBuffer in) {
        return decode(in, true);
    }

    public static IgmpPayload decode(ByteBuffer in, boolean ensureChecksum) {
        IgmpHeader header = IgmpHeader.decode(in);
        IgmpMessage message = IgmpMessage.decode(in, header.type(), header.code());
        IgmpPayload payload = new IgmpPayload(header, message);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(payload));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(payload));
        }
        return payload;
    }
}
