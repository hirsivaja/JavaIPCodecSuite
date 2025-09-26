package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.tcp.option.TcpOption;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record TcpHeader(
        short srcPort,
        short dstPort,
        int sequenceNumber,
        int ackNumber,
        TcpFlags flags,
        short windowSize,
        short checksum,
        short urgentPointer,
        List<TcpOption> options) {
    public static final int TCP_HEADER_LEN = 20;
    private static final int DATA_OFFSET_SHIFT = 4;

    public TcpHeader(short srcPort, short dstPort, int sequenceNumber, int ackNumber, TcpFlags flags, short windowSize,
                     short urgentPointer) {
        this(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, (short) 0, urgentPointer, List.of());
    }

    @SuppressWarnings("squid:S00107")
    public TcpHeader(short srcPort, short dstPort, int sequenceNumber, int ackNumber, TcpFlags flags, short windowSize,
                     short urgentPointer, List<TcpOption> options) {
        this(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, (short) 0, urgentPointer, options);
    }

    public void encode(ByteBuffer out) {
        out.putShort(srcPort);
        out.putShort(dstPort);
        out.putInt(sequenceNumber);
        out.putInt(ackNumber);
        out.put((byte) (((optionsLength() / 4) + 5) << DATA_OFFSET_SHIFT));
        out.put(flags.toByte());
        out.putShort(windowSize);
        out.putShort(checksum);
        out.putShort(urgentPointer);
        options.forEach(option -> option.encode(out));
    }

    public int length() {
        return TCP_HEADER_LEN + optionsLength();
    }

    public int optionsLength() {
        return options.stream().mapToInt(TcpOption::length).sum();
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
        List<TcpOption> options = new ArrayList<>();
        int optionsLength = (dataOffset - 5) * 4;
        while(optionsLength > 0) {
            TcpOption option = TcpOption.decode(in);
            options.add(option);
            optionsLength -= option.length();
        }
        if(optionsLength != 0) {
            throw new IllegalArgumentException("Could not decode options for the TCP header.");
        }
        return new TcpHeader(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, options);
    }

    public int uSrcPort() {
        return Short.toUnsignedInt(srcPort);
    }

    public int uDstPort() {
        return Short.toUnsignedInt(dstPort);
    }
}
