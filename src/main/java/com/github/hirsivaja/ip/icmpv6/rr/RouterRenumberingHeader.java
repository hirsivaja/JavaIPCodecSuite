package com.github.hirsivaja.ip.icmpv6.rr;

import java.nio.ByteBuffer;

public record RouterRenumberingHeader(
        int sequenceNumber,
        byte segmentNumber,
        byte flags,
        short maxDelay) {

    public void encode(ByteBuffer out) {
        out.putInt(sequenceNumber);
        out.put(segmentNumber);
        out.put(flags);
        out.putShort(maxDelay);
        out.putInt(0); // RESERVED
    }

    public int length() {
        return 12;
    }

    public static RouterRenumberingHeader decode(ByteBuffer in) {
        int sequenceNumber = in.getInt();
        byte segmentNumber = in.get();
        byte flags = in.get();
        short maxDelay = in.getShort();
        in.getInt(); // RESERVED
        return new RouterRenumberingHeader(sequenceNumber, segmentNumber, flags, maxDelay);
    }
}
