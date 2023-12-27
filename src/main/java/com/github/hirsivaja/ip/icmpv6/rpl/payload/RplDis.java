package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class RplDis implements RplPayload {
    private static final int MIN_LEN = 2;
    private final RplSecurity security;
    private final List<RplOption> options;

    public RplDis(List<RplOption> options) {
        this(null, options);
    }

    public RplDis(RplSecurity security, List<RplOption> options) {
        this.security = security;
        this.options = options;
    }

    public void encode(ByteBuffer out){
        if(security != null) {
            security.encode(out);
        }
        out.put((byte) 0); // FLAGS are ignored
        out.put((byte) 0); // RESERVED
        options.forEach(option -> option.encode(out));
    }

    @Override
    public RplPayloadType getType() {
        if(security == null) {
            return RplPayloadType.DIS;
        } else {
            return RplPayloadType.SECURE_DIS;
        }
    }

    @Override
    public int getLength() {
        int securityLen = security == null ? 0 : security.getLength();
        return securityLen + MIN_LEN +
                options.stream().mapToInt(RplOption::getLength).sum();
    }

    public static RplDis decode(ByteBuffer in, boolean hasSecurity){
        RplSecurity security = null;
        if(hasSecurity) {
            security = RplSecurity.decode(in);
        }
        in.get(); // FLAGS are ignored
        in.get(); // RESERVED
        List<RplOption> options = new ArrayList<>();
        while(in.hasRemaining()){
            options.add(RplOption.decode(in));
        }
        return new RplDis(security, options);
    }

    @Override
    public RplSecurity getSecurity() {
        return security;
    }

    @Override
    public List<RplOption> getOptions() {
        return options;
    }
}
