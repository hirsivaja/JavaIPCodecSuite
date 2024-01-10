package com.github.hirsivaja.ip.tcp;

import java.nio.ByteBuffer;

public class TcpHeader {
    public static final int TCP_HEADER_LEN = 20;
    private static final int DATA_OFFSET_SHIFT = 4;
    private final short srcPort;
    private final short dstPort;
    private final int sequenceNumber;
    private final int ackNumber;
    private final TcpFlags flags;
    private final short windowSize;
    private final short checksum;
    private final short urgentPointer;
    private final byte[] options;

    @SuppressWarnings("squid:S00107")
    public TcpHeader(short srcPort, short dstPort, int sequenceNumber, int ackNumber, TcpFlags flags, short windowSize,
                     short urgentPointer, byte[] options) {
        this(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, (short) 0, urgentPointer, options);
    }

    @SuppressWarnings("squid:S00107")
    public TcpHeader(short srcPort, short dstPort, int sequenceNumber, int ackNumber, TcpFlags flags, short windowSize,
                     short checksum, short urgentPointer, byte[] options) {
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.sequenceNumber = sequenceNumber;
        this.ackNumber = ackNumber;
        this.flags = flags;
        this.windowSize = windowSize;
        this.checksum = checksum;
        this.urgentPointer = urgentPointer;
        this.options = options;
    }

    public void encode(ByteBuffer out) {
        out.putShort(srcPort);
        out.putShort(dstPort);
        out.putInt(sequenceNumber);
        out.putInt(ackNumber);
        out.put((byte) (((options.length / 4) + 5) << DATA_OFFSET_SHIFT));
        out.put(flags.toByte());
        out.putShort(windowSize);
        out.putShort(checksum);
        out.putShort(urgentPointer);
        out.put(options);
    }

    public int getLength() {
        return TCP_HEADER_LEN + options.length;
    }

    public static TcpHeader decode(ByteBuffer in) {
        short srcPort = in.getShort();
        short dstPort = in.getShort();
        int sequenceNumber = in.getInt();
        int ackNumber = in.getInt();
        int dataOffset = (in.get() >>> DATA_OFFSET_SHIFT) & 0x0F;
        TcpFlags flags = TcpFlags.decode(in.get());
        short windowSize = in.getShort();
        short checksum = in.getShort();
        short urgentPointer = in.getShort();
        byte[] options = new byte[(dataOffset - 5) * 4];
        in.get(options);
        return new TcpHeader(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, options);
    }

    public int getSrcPort() {
        return Short.toUnsignedInt(srcPort);
    }

    public int getDstPort() {
        return Short.toUnsignedInt(dstPort);
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public int getAckNumber() {
        return ackNumber;
    }

    public TcpFlags getFlags() {
        return flags;
    }

    public short getWindowSize() {
        return windowSize;
    }

    public short getChecksum() {
        return checksum;
    }

    public short getUrgentPointer() {
        return urgentPointer;
    }

    public byte[] getOptions() {
        return options;
    }
}
