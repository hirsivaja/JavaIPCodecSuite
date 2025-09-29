package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Packet;

import java.nio.ByteBuffer;

public record IgmpPacket(Ipv4Header header, IgmpMessage message) implements Ipv4Packet {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.put(message.type().type());
        out.put(message.code());
        out.putShort(IpUtils.calculateInternetChecksum(generateChecksumData(message, (short) 0)));
        message.encode(out);
    }

    private static byte[] generateChecksumData(IgmpMessage message, short checksum) {
        ByteBuffer checksumBuf = ByteBuffer.allocate(message.length());
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

    public static Ipv4Packet decode(ByteBuffer in, Ipv4Header header) {
        return decode(in, header, true);
    }

    public static Ipv4Packet decode(ByteBuffer in, Ipv4Header header, boolean ensureChecksum) {
        IgmpType type = IgmpType.fromType(in.get());
        byte code = in.get();
        short checksum = in.getShort();
        IgmpMessage message = IgmpMessage.decode(in, type, code);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(generateChecksumData(message, checksum));
        } else {
            IpUtils.verifyInternetChecksum(generateChecksumData(message, checksum));
        }
        return new IgmpPacket(header, message);
    }
}
