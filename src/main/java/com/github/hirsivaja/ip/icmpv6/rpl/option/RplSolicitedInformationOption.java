package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplSolicitedInformationOption implements RplOption {
    private static final int LEN = 19;
    private static final int DODAG_ID_LEN = 16;
    private final byte rplInstanceId;
    private final byte flags;
    private final byte[] dodagId;
    private final byte versionNumber;

    public RplSolicitedInformationOption(byte rplInstanceId, byte flags, byte[] dodagId, byte versionNumber) {
        this.rplInstanceId = rplInstanceId;
        this.flags = flags;
        this.dodagId = dodagId;
        this.versionNumber = versionNumber;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) LEN);
        out.put(rplInstanceId);
        out.put(flags);
        out.put(dodagId);
        out.put(versionNumber);
    }

    @Override
    public int getLength() {
        return 21;
    }

    @Override
    public RplOptionType getOptionType() {
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

    public byte getRplInstanceId() {
        return rplInstanceId;
    }

    public byte getFlags() {
        return flags;
    }

    public byte[] getDodagId() {
        return dodagId;
    }

    public byte getVersionNumber() {
        return versionNumber;
    }
}
