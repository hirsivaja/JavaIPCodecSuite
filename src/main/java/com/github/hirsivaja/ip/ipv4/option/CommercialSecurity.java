package com.github.hirsivaja.ip.ipv4.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record CommercialSecurity(byte domainOfInterpretation, ByteArray tags) implements IpOption {

    public CommercialSecurity(byte domainOfInterpretation, byte[] tags) {
        this(domainOfInterpretation, new ByteArray(tags));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(domainOfInterpretation);
        out.put(tags.array());
    }

    @Override
    public int length() {
        return 3 + tags.length();
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.COMMERCIAL_SECURITY;
    }

    public static CommercialSecurity decode(ByteBuffer in){
        byte domainOfInterpretation = in.get();
        byte[] tags = new byte[in.remaining()];
        in.get(tags);
        return new CommercialSecurity(domainOfInterpretation, tags);
    }
}
