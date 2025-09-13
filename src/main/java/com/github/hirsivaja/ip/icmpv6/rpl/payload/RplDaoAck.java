package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.Dodagid;

import java.nio.ByteBuffer;

public record RplDaoAck(
        byte rplInstance,
        byte flags,
        byte daoSequence,
        byte status,
        Dodagid dodagid) implements RplBase {
    private static final int MIN_LEN = 4;

    public void encode(ByteBuffer out){
        out.put(rplInstance);
        out.put(flags);
        out.put(daoSequence);
        out.put(status);
        if(dodagid != null) {
            out.put(dodagid.rawDodagid());
        }
    }

    @Override
    public Icmpv6Code code(boolean secured) {
        if(secured) {
            return Icmpv6Codes.SECURE_DAO_ACK;
        } else {
            return Icmpv6Codes.DAO_ACK;
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

    public static RplDaoAck decode(ByteBuffer in){
        byte rplInstance = in.get();
        byte flags = in.get();
        byte daoSequence = in.get();
        byte status = in.get();
        boolean hasDodagid = (flags & 0x80) > 0;
        Dodagid dodagid = null;
        if(hasDodagid) {
            dodagid = Dodagid.decode(in);
            
        }
        return new RplDaoAck(rplInstance, flags, daoSequence, status, dodagid);
    }
}
