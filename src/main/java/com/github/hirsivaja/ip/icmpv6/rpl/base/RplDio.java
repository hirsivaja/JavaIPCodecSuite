package com.github.hirsivaja.ip.icmpv6.rpl.base;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.Dodagid;

import java.nio.ByteBuffer;

public record RplDio(
        byte rplInstance,
        byte versionNumber,
        short rank,
        byte flags,
        byte dtsn,
        Dodagid dodagid) implements RplBase {
    private static final int MIN_LEN = 8;

    @Override
    public void encode(ByteBuffer out){
        out.put(rplInstance);
        out.put(versionNumber);
        out.putShort(rank);
        out.put(flags);
        out.put(dtsn);
        out.putShort((short) 0); // RESERVED
        out.put(dodagid.rawDodagid());
    }

    @Override
    public Icmpv6Code code(boolean secured) {
        if(secured) {
            return Icmpv6Codes.SECURE_DIO;
        } else {
            return Icmpv6Codes.DIO;
        }
    }

    @Override
    public int length() {
        return MIN_LEN + Dodagid.DODAGID_LEN;
    }

    @Override
    public boolean hasDodagid() {
        return true;
    }

    public static RplDio decode(ByteBuffer in){
        byte rplInstance = in.get();
        byte versionNumber = in.get();
        short rank = in.getShort();
        byte flags = in.get();
        byte dtsn = in.get();
        in.getShort(); // RESERVED
        Dodagid dodagid = Dodagid.decode(in);
        return new RplDio(rplInstance, versionNumber, rank, flags, dtsn, dodagid);
    }
}
