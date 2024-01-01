package com.github.hirsivaja.ip.ethernet;

import java.nio.ByteBuffer;

public class EthernetFrame {
    private static final int TP_ID = 0x8100;
    private static final int MINIMUM_FRAME_SIZE = 64;
    private static final int FRAME_BASE_SIZE = 18;
    private final MacAddress destination;
    private final MacAddress source;
    private final boolean hasDot1qTag;
    private final short dot1qTag;
    private final short etherType;
    private final EthernetPayload payload;
    private final int crc;

    public EthernetFrame(MacAddress destination, MacAddress source, short etherType, EthernetPayload payload, int crc) {
        this.destination = destination;
        this.source = source;
        this.hasDot1qTag = false;
        this.dot1qTag = 0;
        this.etherType = etherType;
        this.payload = payload;
        this.crc = crc;
    }

    public EthernetFrame(MacAddress destination, MacAddress source, short dot1qTag, short etherType, EthernetPayload payload, int crc) {
        this.destination = destination;
        this.source = source;
        this.hasDot1qTag = true;
        this.dot1qTag = dot1qTag;
        this.etherType = etherType;
        this.payload = payload;
        this.crc = crc;
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
        int paddingLen = MINIMUM_FRAME_SIZE - payload.getLength() - (hasDot1qTag ? 4 : 0) - FRAME_BASE_SIZE;
        byte[] padding = new byte[Math.max(paddingLen, 0)];
        out.put(padding);
        if(crc != 0) {
            out.putInt(crc);
        }
    }

    public int getLength() {
        int len = FRAME_BASE_SIZE + payload.getLength() + (hasDot1qTag ? 4 : 0) + (crc == 0 ? -4 : 0);
        return Math.max(len, MINIMUM_FRAME_SIZE);
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
        int paddingLen = MINIMUM_FRAME_SIZE - payload.getLength() - (hasDot1qTag ? 4 : 0) - FRAME_BASE_SIZE;
        byte[] padding = new byte[Math.max(paddingLen, 0)];
        in.get(padding);
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

    public MacAddress getDestination() {
        return destination;
    }

    public MacAddress getSource() {
        return source;
    }

    public boolean hasDot1qTag() {
        return hasDot1qTag;
    }

    public short getDot1qTag() {
        return dot1qTag;
    }

    public EthernetPayload getPayload() {
        return payload;
    }

    public int getCrc() {
        return crc;
    }
}
