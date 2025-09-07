package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RplDio(
        RplSecurity security,
        byte rplInstance,
        byte versionNumber,
        short rank,
        byte flags,
        byte dtsn,
        ByteArray dodagId,
        List<RplOption> options) implements RplPayload {
    private static final int MIN_LEN = 8;

    public RplDio(byte rplInstance, byte versionNumber, short rank, byte flags, byte dtsn,
                  byte[] dodagId, List<RplOption> options) {
        this(null, rplInstance, versionNumber, rank, flags, dtsn, new ByteArray(dodagId), options);
    }

    public RplDio(RplSecurity security, byte rplInstance, byte versionNumber, short rank, byte flags, byte dtsn,
                  byte[] dodagId, List<RplOption> options) {
        this(security, rplInstance, versionNumber, rank, flags, dtsn, new ByteArray(dodagId), options);
    }

    @Override
    public void encode(ByteBuffer out){
        if(security != null) {
            security.encode(out);
        }
        out.put(rplInstance);
        out.put(versionNumber);
        out.putShort(rank);
        out.put(flags);
        out.put(dtsn);
        out.putShort((short) 0); // RESERVED
        out.put(dodagId.array());
        options.forEach(option -> option.encode(out));
    }

    @Override
    public RplPayloadType type() {
        if(security == null) {
            return RplPayloadType.DIO;
        } else {
            return RplPayloadType.SECURE_DIO;
        }
    }

    @Override
    public int length() {
        int securityLen = security == null ? 0 : security.length();
        return securityLen + MIN_LEN + dodagId.length() +
                options.stream().mapToInt(RplOption::length).sum();
    }

    public static RplDio decode(ByteBuffer in, boolean hasSecurity){
        RplSecurity security = null;
        if(hasSecurity) {
            security = RplSecurity.decode(in);
        }
        byte rplInstance = in.get();
        byte versionNumber = in.get();
        short rank = in.getShort();
        byte flags = in.get();
        byte dtsn = in.get();
        in.getShort(); // RESERVED
        byte[] dodagId = new byte[DODAG_ID_LEN];
        in.get(dodagId);
        List<RplOption> options = new ArrayList<>();
        while(in.hasRemaining()){
            options.add(RplOption.decode(in));
        }
        return new RplDio(security, rplInstance, versionNumber, rank, flags, dtsn, dodagId, options);
    }

    public byte[] rawDodagId() {
        return dodagId.array();
    }
}
