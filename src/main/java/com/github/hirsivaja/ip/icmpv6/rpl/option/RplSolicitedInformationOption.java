package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.icmpv6.rpl.Dodagid;
import java.nio.ByteBuffer;

public record RplSolicitedInformationOption(
        byte rplInstanceId,
        byte flags,
        Dodagid dodagid,
        byte versionNumber) implements RplOption {
    private static final int LEN = 19;

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) LEN);
        out.put(rplInstanceId);
        out.put(flags);
        dodagid.encode(out);
        out.put(versionNumber);
    }

    @Override
    public int length() {
        return 21;
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.SOLICITED_INFORMATION;
    }

    public static RplSolicitedInformationOption decode(ByteBuffer in){
        byte len = in.get();
        if(len != LEN){
            throw new IllegalArgumentException("Invalid length " + len);
        }
        byte rplInstanceId = in.get();
        byte flags = in.get();
        Dodagid dodagid = Dodagid.decode(in);
        byte versionNumber = in.get();
        return new RplSolicitedInformationOption(rplInstanceId, flags, dodagid, versionNumber);
    }
}
