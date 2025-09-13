package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.Dodagid;

import java.nio.ByteBuffer;

public record RplConsistencyCheck(
        byte rplInstance,
        byte flags,
        short ccNonce,
        Dodagid dodagid,
        int destinationCounter) implements RplBase {
    private static final int MIN_LEN = 24;

    @Override
    public void encode(ByteBuffer out){
        out.put(rplInstance);
        out.put(flags);
        out.putShort(ccNonce);
        out.put(dodagid.rawDodagid());
        out.putInt(destinationCounter);
    }

    @Override
    public Icmpv6Code code(boolean secured) {
        return Icmpv6Codes.CONSISTENCY_CHECK;
    }

    @Override
    public int length() {
        return MIN_LEN;
    }

    @Override
    public boolean hasDodagid() {
        return true;
    }

    public static RplConsistencyCheck decode(ByteBuffer in){
        byte rplInstance = in.get();
        byte flags = in.get();
        short ccNonce = in.getShort();
        Dodagid dodagid = Dodagid.decode(in);
        int destinationCounter = in.getInt();
        return new RplConsistencyCheck(rplInstance, flags, ccNonce, dodagid, destinationCounter);
    }
}
