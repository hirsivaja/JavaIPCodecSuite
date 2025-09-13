package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RplDaoAck(
        RplSecurity security,
        byte rplInstance,
        byte flags,
        byte daoSequence,
        byte status,
        ByteArray dodagId,
        List<RplOption> options) implements RplPayload {
    private static final int MIN_LEN = 4;

    public RplDaoAck(byte rplInstance, byte flags, byte daoSequence, byte status, byte[] dodagId, List<RplOption> options) {
        this(null, rplInstance, flags, daoSequence, status, dodagId, options);
    }

    public RplDaoAck(RplSecurity security, byte rplInstance, byte flags, byte daoSequence, byte status,
                     byte[] dodagId, List<RplOption> options) {
        this(security, rplInstance, flags, daoSequence, status, new ByteArray(dodagId), options);
    }

    public void encode(ByteBuffer out){
        if(security != null) {
            security.encode(out);
        }
        out.put(rplInstance);
        out.put(flags);
        out.put(daoSequence);
        out.put(status);
        out.put(dodagId.array());
        options.forEach(option -> option.encode(out));
    }

    @Override
    public Icmpv6Code code() {
        if(security == null) {
            return Icmpv6Codes.DAO_ACK;
        } else {
            return Icmpv6Codes.SECURE_DAO_ACK;
        }
    }

    @Override
    public int length() {
        int securityLen = security == null ? 0 : security.length();
        return securityLen + MIN_LEN + dodagId.length() +
                options.stream().mapToInt(RplOption::length).sum();
    }

    public static RplDaoAck decode(ByteBuffer in, boolean hasSecurity){
        RplSecurity security = null;
        if(hasSecurity) {
            security = RplSecurity.decode(in);
        }
        byte rplInstance = in.get();
        byte flags = in.get();
        byte daoSequence = in.get();
        byte status = in.get();
        int dodagLen = (flags & 0x80) > 0 ? DODAG_ID_LEN : 0;
        byte[] dodagId = new byte[dodagLen];
        in.get(dodagId);
        List<RplOption> options = new ArrayList<>();
        while(in.hasRemaining()){
            options.add(RplOption.decode(in));
        }
        return new RplDaoAck(security, rplInstance, flags, daoSequence, status, dodagId, options);
    }

    public byte[] rawDodagId() {
        return dodagId.array();
    }
}
