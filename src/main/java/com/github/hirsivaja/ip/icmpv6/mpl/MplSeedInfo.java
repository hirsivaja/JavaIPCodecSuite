package com.github.hirsivaja.ip.icmpv6.mpl;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record MplSeedInfo(byte minSequenceNumber, ByteArray seedId, ByteArray mplMessages) {

    private MplSeedInfo(byte minSequenceNumber, byte[] seedId, byte[] mplMessages) {
        this(minSequenceNumber, new ByteArray(seedId), new ByteArray(mplMessages));
    }

    public void encode(ByteBuffer out) {
        out.put(minSequenceNumber);
        byte mmSeedLen = switch (seedId.length()) {
            case 0 -> 0;
            case 2 -> 1;
            case 8 -> 2;
            case 16 -> 3;
            default -> throw new IllegalArgumentException();
        };
        mmSeedLen = (byte) (((mplMessages.length() << 2) | mmSeedLen) & 0xFF);
        out.put(mmSeedLen);
        out.put(seedId.array());
        out.put(mplMessages.array());
    }

    public int length() {
        return 2 + seedId.length() + mplMessages.length();
    }

    public static MplSeedInfo decode(ByteBuffer in) {
        byte minSequenceNumber = in.get();
        byte mmSeedLen = in.get();
        int mmLen = (mmSeedLen >> 2) & 0x3F;
        int seedLen = mmSeedLen & 0x03;
        byte[] seedId = switch (seedLen) {
            case 0 -> new byte[0];
            case 1 -> new byte[2];
            case 2 -> new byte[8];
            case 3 -> new byte[16];
            default -> throw new IllegalArgumentException();
        };
        in.get(seedId);
        byte[] mplMessages = new byte[mmLen];
        in.get(mplMessages);
        return new MplSeedInfo(minSequenceNumber, seedId, mplMessages);
    }
}
