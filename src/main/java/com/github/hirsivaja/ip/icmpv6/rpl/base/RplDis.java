package com.github.hirsivaja.ip.icmpv6.rpl.base;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;

import java.nio.ByteBuffer;

public record RplDis() implements RplBase {
    private static final int MIN_LEN = 2;

    public void encode(ByteBuffer out){
        out.put((byte) 0); // FLAGS are ignored
        out.put((byte) 0); // RESERVED
    }

    @Override
    public Icmpv6Code code(boolean secured) {
        if(secured) {
            return Icmpv6Codes.SECURE_DIS;
        } else {
            return Icmpv6Codes.DIS;
        }
    }

    @Override
    public int length() {
        return MIN_LEN;
    }

    @Override
    public boolean hasDodagid() {
        return false;
    }

    public static RplDis decode(ByteBuffer in){
        in.get(); // FLAGS are ignored
        in.get(); // RESERVED
        return new RplDis();
    }
}
