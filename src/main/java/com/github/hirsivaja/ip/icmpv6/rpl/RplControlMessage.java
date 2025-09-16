package com.github.hirsivaja.ip.icmpv6.rpl;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;

import java.nio.ByteBuffer;
import com.github.hirsivaja.ip.icmpv6.rpl.base.RplBase;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;
import java.util.ArrayList;
import java.util.List;

public record RplControlMessage(
        RplSecurity security,
        RplBase base,
        List<RplOption> options) implements Icmpv6Message {

    public RplControlMessage(RplBase base) {
        this(null, base, List.of());
    }

    public RplControlMessage(RplBase base, List<RplOption> options) {
        this(null, base, options);
    }

    @Override
    public void encode(ByteBuffer out) {
        if(security != null) {
            security.encode(out);
        }
        base.encode(out);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        int securityLength = hasSecurity() ? security.length() : 0;
        return BASE_LEN + securityLength + base.length() + options.stream().mapToInt(RplOption::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        RplSecurity security = null;
        if(hasSecurity(code)) {
            security = RplSecurity.decode(in);
        }
        RplBase base = RplBase.decode(in, code);
        List<RplOption> options = new ArrayList<>();
        while(in.hasRemaining()){
            options.add(RplOption.decode(in));
        }
        return new RplControlMessage(security, base, options);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.RPL;
    }

    @Override
    public Icmpv6Code code() {
        return base.code(hasSecurity());
    }

    public boolean hasSecurity() {
        return security() != null;
    }

    public byte[] toByteArray(){
        ByteBuffer out = ByteBuffer.allocate(length() - BASE_LEN);
        encode(out);
        byte[] outBytes = new byte[out.rewind().remaining()];
        out.get(outBytes);
        return outBytes;
    }

    public static RplControlMessage fromByteArray(byte[] rplPayload, Icmpv6Code code){
        return (RplControlMessage) decode(ByteBuffer.wrap(rplPayload), code);
    }

    private static boolean hasSecurity(Icmpv6Code code) {
        return switch(code) {
            case Icmpv6Codes.SECURE_DIS,
                 Icmpv6Codes.SECURE_DIO,
                 Icmpv6Codes.SECURE_DAO,
                 Icmpv6Codes.SECURE_DAO_ACK,
                 Icmpv6Codes.CONSISTENCY_CHECK -> true;
            default -> false; 
        };
    }
}
