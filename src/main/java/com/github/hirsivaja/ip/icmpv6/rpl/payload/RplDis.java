package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RplDis(RplSecurity security, List<RplOption> options) implements RplPayload {
    private static final int MIN_LEN = 2;

    public RplDis(List<RplOption> options) {
        this(null, options);
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
    public Icmpv6Code code() {
        if(security == null) {
            return Icmpv6Codes.DIS;
        } else {
            return Icmpv6Codes.SECURE_DIS;
        }
    }

    @Override
    public int length() {
        int securityLen = security == null ? 0 : security.length();
        return securityLen + MIN_LEN +
                options.stream().mapToInt(RplOption::length).sum();
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
}
