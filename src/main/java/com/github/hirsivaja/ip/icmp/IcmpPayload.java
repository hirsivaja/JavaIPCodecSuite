package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;

import java.nio.ByteBuffer;

public record IcmpPayload(Ipv4Header header, IcmpMessage message) implements Ipv4Payload {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.put(message.type().type());
        out.put(message.code().code());
        out.putShort(IpUtils.calculateInternetChecksum(generateChecksumData(message, (short) 0)));
        message.encode(out);
    }

    private static byte[] generateChecksumData(IcmpMessage message, short checksum) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(message.length());
        checksumBuf.put(message.type().type());
        checksumBuf.put(message.code().code());
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

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
        return decode(in, header, true);
    }

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header, boolean ensureChecksum) {
        IcmpType type = IcmpType.fromType(in.get());
        IcmpCode code = IcmpCode.fromType(type, in.get());
        short checksum = in.getShort();
        IcmpMessage message = IcmpMessage.decode(in, type, code);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(message, checksum));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(message, checksum));
        }
        return new IcmpPayload(header, message);
    }

    public Ipv4Header ipv4Header() {
        return header;
    }
}
