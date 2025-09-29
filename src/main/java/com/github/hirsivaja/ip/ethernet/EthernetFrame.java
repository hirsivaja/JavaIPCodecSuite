package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.IpUtils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public record EthernetFrame(
        MacAddress destination,
        MacAddress source,
        boolean hasDot1qTag,
        short dot1qTag,
        short etherType,
        EthernetPayload payload,
        int crc) {
    private static final Logger logger = Logger.getLogger("EthernetFrame");
    private static final int TP_ID = 0x8100;
    private static final int MINIMUM_FRAME_SIZE = 64;
    private static final int FRAME_BASE_SIZE = 18;

    public EthernetFrame(MacAddress destination, MacAddress source, short etherType, EthernetPayload payload, int crc) {
        this(destination, source, false, (short) 0, etherType, payload, crc);
    }

    public EthernetFrame(MacAddress destination, MacAddress source, short dot1qTag, short etherType, EthernetPayload payload, int crc) {
        this(destination, source, true, dot1qTag, etherType, payload, crc);
    }

    public void encode(ByteBuffer out) {
        destination.encode(out);
        source.encode(out);
        if(hasDot1qTag) {
            out.putShort((short) TP_ID);
            out.putShort(dot1qTag);
        }
        out.putShort(etherType);
        payload.encode(out);
        int paddingLen = MINIMUM_FRAME_SIZE - payload.length() - (hasDot1qTag ? 4 : 0) - FRAME_BASE_SIZE;
        byte[] padding = new byte[Math.max(paddingLen, 0)];
        out.put(padding);
        if(crc != 0) {
            out.putInt(crc);
        }
    }

    public int length() {
        int len = FRAME_BASE_SIZE + payload.length() + (hasDot1qTag ? 4 : 0) + (crc == 0 ? -4 : 0);
        return Math.max(len, MINIMUM_FRAME_SIZE);
    }

    public byte[] toBytes() {
        ByteBuffer out = ByteBuffer.allocate(length());
        encode(out);
        byte[] outBytes = Arrays.copyOfRange(out.array(), 0, out.rewind().remaining());
        if(logger.isLoggable(Level.FINE)) {
            logger.log(Level.FINE, "Ethernet frame as byte array:\n\t{0}", IpUtils.printHexBinary(outBytes));
        }
        return outBytes;
    }

    public String toByteString() {
        return IpUtils.printHexBinary(toBytes());
    }

    public static EthernetFrame fromBytes(byte[] ethernetFrame) {
        if(logger.isLoggable(Level.FINE)) {
            logger.log(Level.FINE, "Creating an Ethernet Frame from:\n\t{0}", IpUtils.printHexBinary(ethernetFrame));
        }
        return decode(ByteBuffer.wrap(ethernetFrame));
    }

    public static EthernetFrame fromByteString(String ipPayload) {
        return fromBytes(IpUtils.parseHexBinary(ipPayload));
    }

    public static EthernetFrame decode(ByteBuffer in) {
        MacAddress destination = MacAddress.decode(in);
        MacAddress source = MacAddress.decode(in);
        int len = Short.toUnsignedInt(in.getShort());
        short dot1qTag = 0;
        boolean hasDot1qTag = len == TP_ID;
        if(hasDot1qTag) {
            dot1qTag = in.getShort();
            len = Short.toUnsignedInt(in.getShort());
        }
        EthernetPayload payload = EthernetPayload.decode(in, len);
        int paddingLen = MINIMUM_FRAME_SIZE - payload.length() - (hasDot1qTag ? 4 : 0) - FRAME_BASE_SIZE;
        if(in.remaining() >= paddingLen) {
            byte[] padding = new byte[Math.max(paddingLen, 0)];
            in.get(padding);
        }
        int crc = 0;
        if(in.remaining() >= 4) {
            crc = in.getInt();
        }
        if(hasDot1qTag) {
            return new EthernetFrame(destination, source, dot1qTag, (short) len, payload, crc);
        } else {
            return new EthernetFrame(destination, source, (short) len, payload, crc);
        }
    }
}
