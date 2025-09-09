package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record TcpHeader(
        short srcPort,
        short dstPort,
        int sequenceNumber,
        int ackNumber,
        TcpFlags flags,
        short windowSize,
        short checksum,
        short urgentPointer,
        ByteArray options) {
    public static final int TCP_HEADER_LEN = 20;
    private static final int DATA_OFFSET_SHIFT = 4;

    @SuppressWarnings("squid:S00107")
    public TcpHeader(short srcPort, short dstPort, int sequenceNumber, int ackNumber, TcpFlags flags, short windowSize,
                     short urgentPointer, byte[] options) {
        this(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, (short) 0, urgentPointer, options);
    }

    @SuppressWarnings("squid:S00107")
    public TcpHeader(short srcPort, short dstPort, int sequenceNumber, int ackNumber, TcpFlags flags, short windowSize,
                     short checksum, short urgentPointer, byte[] options) {
        this(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, new ByteArray(options));
    }

    public void encode(ByteBuffer out) {
        out.putShort(srcPort);
        out.putShort(dstPort);
        out.putInt(sequenceNumber);
        out.putInt(ackNumber);
        out.put((byte) (((options.array().length / 4) + 5) << DATA_OFFSET_SHIFT));
        out.put(flags.toByte());
        out.putShort(windowSize);
        out.putShort(checksum);
        out.putShort(urgentPointer);
        out.put(options.array());
    }

    public int length() {
        return TCP_HEADER_LEN + options.array().length;
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

    public byte[] rawOptions() {
        return options.array();
    }

    public int uSrcPort() {
        return Short.toUnsignedInt(srcPort);
    }

    public int uDstPort() {
        return Short.toUnsignedInt(dstPort);
    }
}
