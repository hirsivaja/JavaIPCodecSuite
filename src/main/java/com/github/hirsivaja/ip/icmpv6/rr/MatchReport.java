package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record MatchReport(
        boolean bFlag,
        boolean fFlag,
        byte ordinal,
        byte matchLength,
        int interfaceIndex,
        Ipv6Address matchedPrefix) {
    public static final int LENGTH = 24;

    public void encode(ByteBuffer out) {
        if(bFlag && fFlag) {
            out.putShort((short) 3);
        } else if(bFlag) {
            out.putShort((short) 2);
        } else if(fFlag) {
            out.putShort((short) 1);
        } else {
            out.putShort((short) 0);
        }
        out.put(ordinal);
        out.put(matchLength);
        out.putInt(interfaceIndex);
        matchedPrefix.encode(out);
    }

    public static MatchReport decode(ByteBuffer in) {
        short reserved = in.getShort();
        boolean bFlag = false;
        boolean fFlag = false;
        switch (reserved & 3) {
            case 3 -> {
                bFlag = true;
                fFlag = true;
            }
            case 2 -> bFlag = true;
            case 1 -> fFlag = true;
            default -> {/* BOTH FLAGS FALSE */}
        }
        byte ordinal = in.get();
        byte matchLength = in.get();
        int interfaceIndex = in.getInt();
        Ipv6Address matchedPrefix = Ipv6Address.decode(in);
        return new MatchReport(bFlag, fFlag, ordinal, matchLength, interfaceIndex, matchedPrefix);
    }
}
