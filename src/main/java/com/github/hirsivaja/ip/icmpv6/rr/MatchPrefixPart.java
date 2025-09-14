package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record MatchPrefixPart(
        byte opCode,
        byte opLength,
        byte ordinal,
        byte matchLength,
        byte minLength,
        byte maxLength,
        Ipv6Address matchPrefix) {

    public void encode(ByteBuffer out) {
        out.put(opCode);
        out.put(opLength);
        out.put(ordinal);
        out.put(matchLength);
        out.put(minLength);
        out.put(maxLength);
        out.putShort((short) 0);
        matchPrefix.encode(out);
    }

    public int length() {
        return 24;
    }

    public static MatchPrefixPart decode(ByteBuffer in) {
        byte opCode = in.get();
        byte opLength = in.get();
        byte ordinal = in.get();
        byte matchLength = in.get();
        byte minLength = in.get();
        byte maxLength = in.get();
        in.getShort(); // RESERVED
        Ipv6Address matchPrefix = Ipv6Address.decode(in);
        return new MatchPrefixPart(opCode, opLength, ordinal, matchLength, minLength, maxLength, matchPrefix);
    }
}
