package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ethernet.EthernetPayload;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public interface IpPayload extends EthernetPayload {
    Logger logger = Logger.getLogger("IpPayload");
    void encode(ByteBuffer out);
    int getLength();
    IpHeader getHeader();

    @Override
    default byte[] toBytes() {
        ByteBuffer out = ByteBuffer.allocate(getLength());
        encode(out);
        byte[] outBytes = Arrays.copyOfRange(out.array(), 0, out.rewind().remaining());
        if(logger.isLoggable(Level.FINE)) {
            logger.fine("IP Payload as byte array:\n\t" + IpUtils.printHexBinary(outBytes));
        }
        return outBytes;
    }

    default String toByteString() {
        return IpUtils.printHexBinary(toBytes());
    }

    static IpPayload fromBytes(byte[] ipPayload) {
        if(logger.isLoggable(Level.FINE)) {
            logger.fine("Creating an IP Payload from:\n\t" + IpUtils.printHexBinary(ipPayload));
        }
        return decode(ByteBuffer.wrap(ipPayload));
    }

    static IpPayload fromByteString(String ipPayload) {
        return fromBytes(IpUtils.parseHexBinary(ipPayload));
    }

    static IpPayload decode(ByteBuffer in) {
        in.mark();
        byte version = (byte) (in.get() >>> Ipv4Header.VERSION_SHIFT);
        in.reset();
        if(version == Ipv4Header.VERSION) {
            return Ipv4Payload.decode(in);
        } else if (version == Ipv6Header.VERSION) {
            return Ipv6Payload.decode(in);
        } else {
            throw new IllegalArgumentException("Not an IP payload");
        }
    }
}
