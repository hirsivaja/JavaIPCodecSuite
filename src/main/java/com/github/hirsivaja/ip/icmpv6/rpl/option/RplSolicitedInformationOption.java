package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record RplSolicitedInformationOption(
        byte rplInstanceId,
        byte flags,
        ByteArray dodagId,
        byte versionNumber) implements RplOption {
    private static final int LEN = 19;
    private static final int DODAG_ID_LEN = 16;

    public RplSolicitedInformationOption(byte rplInstanceId, byte flags, byte[] dodagId, byte versionNumber) {
        this(rplInstanceId, flags, new ByteArray(dodagId), versionNumber);
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) LEN);
        out.put(rplInstanceId);
        out.put(flags);
        out.put(dodagId.array());
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
        byte[] dodagId = new byte[DODAG_ID_LEN];
        in.get(dodagId);
        byte versionNumber = in.get();
        return new RplSolicitedInformationOption(rplInstanceId, flags, dodagId, versionNumber);
    }

    public byte[] rawDodagId() {
        return dodagId.array();
    }
}
