package com.github.hirsivaja.ip.ipv4.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record ExtendedSecurity(byte additionalSecurityInfoFormatCode, ByteArray additionalSecurityInformation) implements IpOption {

    public ExtendedSecurity(byte additionalSecurityInfoFormatCode, byte[] additionalSecurityInformation) {
        this(additionalSecurityInfoFormatCode, new ByteArray(additionalSecurityInformation));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(additionalSecurityInfoFormatCode);
        out.put(additionalSecurityInformation.array());
    }

    @Override
    public int length() {
        return 3 + additionalSecurityInformation.length();
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.EXTENDED_SECURITY;
    }

    public static ExtendedSecurity decode(ByteBuffer in){
        byte additionalSecurityInfoFormatCode = in.get();
        byte[] additionalSecurityInformation = new byte[in.remaining()];
        in.get(additionalSecurityInformation);
        return new ExtendedSecurity(additionalSecurityInfoFormatCode, additionalSecurityInformation);
    }
}
