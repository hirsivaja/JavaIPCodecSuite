package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class RplDaoAck implements RplPayload {
    private static final int MIN_LEN = 4;
    private final RplSecurity security;
    private final byte rplInstance;
    private final byte flags;
    private final byte daoSequence;
    private final byte status;
    private final byte[] dodagId;
    private final List<RplOption> options;

    public RplDaoAck(byte rplInstance, byte flags, byte daoSequence, byte status, byte[] dodagId, List<RplOption> options) {
        this(null, rplInstance, flags, daoSequence, status, dodagId, options);
    }

    public RplDaoAck(RplSecurity security, byte rplInstance, byte flags, byte daoSequence, byte status,
                     byte[] dodagId, List<RplOption> options) {
        this.security = security;
        this.rplInstance = rplInstance;
        this.flags = flags;
        this.daoSequence = daoSequence;
        this.status = status;
        this.dodagId = dodagId;
        this.options = options;
    }

    public void encode(ByteBuffer out){
        if(security != null) {
            security.encode(out);
        }
        out.put(rplInstance);
        out.put(flags);
        out.put(daoSequence);
        out.put(status);
        out.put(dodagId);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public RplPayloadType getType() {
        if(security == null) {
            return RplPayloadType.DAO_ACK;
        } else {
            return RplPayloadType.SECURE_DAO_ACK;
        }
    }

    @Override
    public int getLength() {
        int securityLen = security == null ? 0 : security.getLength();
        return securityLen + MIN_LEN + dodagId.length +
                options.stream().mapToInt(RplOption::getLength).sum();
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

    @Override
    public RplSecurity getSecurity() {
        return security;
    }

    public byte getRplInstance() {
        return rplInstance;
    }

    public byte getFlags() {
        return flags;
    }

    public byte getDaoSequence() {
        return daoSequence;
    }

    public byte getStatus() {
        return status;
    }

    public byte[] getDodagId() {
        return dodagId;
    }

    @Override
    public List<RplOption> getOptions() {
        return options;
    }
}
