package com.github.hirsivaja.ip.icmpv6.rpl.base;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.Dodagid;

import java.nio.ByteBuffer;

public record RplDao(
        byte rplInstance,
        byte flags,
        byte daoSequence,
        Dodagid dodagid) implements RplBase {
    private static final int MIN_LEN = 4;

    public void encode(ByteBuffer out){
        out.put(rplInstance);
        out.put(flags);
        out.put((byte) 0); // RESERVED
        out.put(daoSequence);
        if(dodagid != null) {
            out.put(dodagid.rawDodagid());
        }
    }

    @Override
    public Icmpv6Code code(boolean secured) {
        if(secured) {
            return Icmpv6Codes.SECURE_DAO;
        } else {
            return Icmpv6Codes.DAO;
        }
    }

    @Override
    public int length() {
        return MIN_LEN + (dodagid == null ? 0 : dodagid.length());
    }

    @Override
    public boolean hasDodagid() {
        return dodagid != null;
    }

    public static RplDao decode(ByteBuffer in){
        byte rplInstance = in.get();
        byte flags = in.get();
        in.get(); // RESERVED
        byte daoSequence = in.get();
        boolean hasDodagid = (flags & 0x40) > 0;
        Dodagid dodagid = null;
        if(hasDodagid) {
            dodagid = Dodagid.decode(in);
            
        }
        return new RplDao(rplInstance, flags, daoSequence, dodagid);
    }
}
