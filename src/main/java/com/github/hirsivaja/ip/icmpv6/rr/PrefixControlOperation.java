package com.github.hirsivaja.ip.icmpv6.rr;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record PrefixControlOperation(MatchPrefixPart matchPrefixPart, List<UsePrefixPart> usePrefixParts) {

    public void encode(ByteBuffer out) {
        matchPrefixPart.encode(out);
        usePrefixParts.forEach(usePrefixPart -> usePrefixPart.encode(out));
    }

    public int length() {
        return matchPrefixPart.length() + usePrefixParts.stream().mapToInt(UsePrefixPart::length).sum();
    }

    public static PrefixControlOperation decode(ByteBuffer in) {
        MatchPrefixPart matchPrefixPart = MatchPrefixPart.decode(in);
        int numberOfUsePrefixParts = Byte.toUnsignedInt(matchPrefixPart.opLength()) - matchPrefixPart.length();
        numberOfUsePrefixParts = numberOfUsePrefixParts / UsePrefixPart.LEN;
        List<UsePrefixPart> usePrefixParts = new ArrayList<>();
        for(int i = 0; i < numberOfUsePrefixParts; i++) {
            usePrefixParts.add(UsePrefixPart.decode(in));
        }
        return new PrefixControlOperation(matchPrefixPart, usePrefixParts);
    }
}
