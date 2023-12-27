package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class RplDio implements RplPayload {
    private static final int MIN_LEN = 8;
    private final RplSecurity security;
    private final byte rplInstance;
    private final byte versionNumber;
    private final short rank;
    private final byte flags;
    private final byte dtsn;
    private final byte[] dodagId;
    private final List<RplOption> options;

    public RplDio(byte rplInstance, byte versionNumber, short rank, byte flags, byte dtsn,
                  byte[] dodagId, List<RplOption> options) {
        this(null, rplInstance, versionNumber, rank, flags, dtsn, dodagId, options);
    }

    @SuppressWarnings("squid:S00107")
    public RplDio(RplSecurity security, byte rplInstance, byte versionNumber, short rank, byte flags, byte dtsn,
                  byte[] dodagId, List<RplOption> options) {
        this.security = security;
        this.rplInstance = rplInstance;
        this.versionNumber = versionNumber;
        this.rank = rank;
        this.flags = flags;
        this.dtsn = dtsn;
        this.dodagId = dodagId;
        this.options = options;
    }

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
        out.put(dodagId);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public RplPayloadType getType() {
        if(security == null) {
            return RplPayloadType.DIO;
        } else {
            return RplPayloadType.SECURE_DIO;
        }
    }

    @Override
    public int getLength() {
        int securityLen = security == null ? 0 : security.getLength();
        return securityLen + MIN_LEN + dodagId.length +
                options.stream().mapToInt(RplOption::getLength).sum();
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

    @Override
    public RplSecurity getSecurity() {
        return security;
    }

    public byte getRplInstance() {
        return rplInstance;
    }

    public byte getVersionNumber() {
        return versionNumber;
    }

    public short getRank() {
        return rank;
    }

    public byte getFlags() {
        return flags;
    }

    public byte getDtsn() {
        return dtsn;
    }

    public byte[] getDodagId() {
        return dodagId;
    }

    @Override
    public List<RplOption> getOptions() {
        return options;
    }
}
