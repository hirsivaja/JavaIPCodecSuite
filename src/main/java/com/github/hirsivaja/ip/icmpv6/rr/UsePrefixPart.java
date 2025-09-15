package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record UsePrefixPart(
        byte useLength,
        byte keepLength,
        byte flagMask,
        byte raFlags,
        int validLifetime,
        int preferredLifetime,
        boolean vFlag,
        boolean pFlag, Ipv6Address usePrefix) {
    public static final int LEN = 32;
    private static final int VP = 0xC0000000;
    private static final int V = 0x80000000;
    private static final int P = 0x40000000;

    public void encode(ByteBuffer out) {
        out.put(useLength);
        out.put(keepLength);
        out.put(flagMask);
        out.put(raFlags);
        out.putInt(validLifetime);
        out.putInt(preferredLifetime);
        if(vFlag && pFlag) {
            out.putInt(VP);
        } else if(vFlag) {
            out.putInt(V);
        } else if(pFlag) {
            out.putInt(P);
        } else {
            out.putInt(0);
        }
        usePrefix.encode(out);
    }

    public int length() {
        return LEN;
    }

    public static UsePrefixPart decode(ByteBuffer in) {
        byte useLength = in.get();
        byte keepLength = in.get();
        byte flagMask = in.get();
        byte raFlags = in.get();
        int validLifetime = in.getInt();
        int preferredLifetime = in.getInt();
        int reserved = in.getInt();
        boolean vFlag = false;
        boolean pFlag = false;
        switch (reserved) {
            case VP -> {
                vFlag = true;
                pFlag = true;
            }
            case V -> vFlag = true;
            case P -> pFlag = true;
            default -> {/* BOTH FLAGS FALSE */}
        }
        Ipv6Address usePrefix = Ipv6Address.decode(in);
        return new UsePrefixPart(useLength, keepLength, flagMask, raFlags, validLifetime, preferredLifetime, vFlag, pFlag, usePrefix);
    }
}
