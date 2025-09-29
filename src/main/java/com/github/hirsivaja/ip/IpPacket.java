package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ethernet.EthernetPayload;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Packet;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public sealed interface IpPacket extends EthernetPayload permits Ipv4Packet, Ipv6Packet {
    Logger logger = Logger.getLogger("IpPacket");
    IpHeader header();

    @Override
    default byte[] toBytes() {
        ByteBuffer out = ByteBuffer.allocate(length());
        encode(out);
        byte[] outBytes = Arrays.copyOfRange(out.array(), 0, out.rewind().remaining());
        if(logger.isLoggable(Level.FINE)) {
            logger.log(Level.FINE, "IP packet as byte array:\n\t{0}", IpUtils.printHexBinary(outBytes));
        }
        return outBytes;
    }

    default String toByteString() {
        return IpUtils.printHexBinary(toBytes());
    }

    static IpPacket fromBytes(byte[] ipPayload) {
        if(logger.isLoggable(Level.FINE)) {
            logger.log(Level.FINE, "Creating an IP packet from:\n\t{0}", IpUtils.printHexBinary(ipPayload));
        }
        return decode(ByteBuffer.wrap(ipPayload));
    }

    static IpPacket fromByteString(String ipPayload) {
        return fromBytes(IpUtils.parseHexBinary(ipPayload));
    }

    static IpPacket decode(ByteBuffer in) {
        return decode(in, true);
    }

    static IpPacket decode(ByteBuffer in, boolean ensureChecksum) {
        in.mark();
        byte version = (byte) (in.get() >>> Ipv4Header.VERSION_SHIFT);
        in.reset();
        return switch (version) {
            case Ipv4Header.VERSION -> Ipv4Packet.decode(in, ensureChecksum);
            case Ipv6Header.VERSION -> Ipv6Packet.decode(in, ensureChecksum);
            default -> throw new IllegalArgumentException("Not an IP data");
        };
    }
}
