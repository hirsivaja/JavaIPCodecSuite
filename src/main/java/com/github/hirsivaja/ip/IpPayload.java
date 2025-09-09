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

public sealed interface IpPayload extends EthernetPayload permits Ipv4Payload, Ipv6Payload {
    Logger logger = Logger.getLogger("IpPayload");
    IpHeader header();

    @Override
    default byte[] toBytes() {
        ByteBuffer out = ByteBuffer.allocate(length());
        encode(out);
        byte[] outBytes = Arrays.copyOfRange(out.array(), 0, out.rewind().remaining());
        if(logger.isLoggable(Level.FINE)) {
            logger.log(Level.FINE, "IP Payload as byte array:\n\t{0}", IpUtils.printHexBinary(outBytes));
        }
        return outBytes;
    }

    default String toByteString() {
        return IpUtils.printHexBinary(toBytes());
    }

    static IpPayload fromBytes(byte[] ipPayload) {
        if(logger.isLoggable(Level.FINE)) {
            logger.log(Level.FINE, "Creating an IP Payload from:\n\t{0}", IpUtils.printHexBinary(ipPayload));
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
        return switch (version) {
            case Ipv4Header.VERSION -> Ipv4Payload.decode(in);
            case Ipv6Header.VERSION -> Ipv6Payload.decode(in);
            default -> throw new IllegalArgumentException("Not an IP payload");
        };
    }
}
