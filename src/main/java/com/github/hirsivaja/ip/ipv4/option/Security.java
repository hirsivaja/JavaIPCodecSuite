package com.github.hirsivaja.ip.ipv4.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record Security(byte classificationLevel, ByteArray protectionAuthorityFlags) implements IpOption {

    public Security(byte classificationLevel, byte[] protectionAuthorityFlags) {
        this(classificationLevel, new ByteArray(protectionAuthorityFlags));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(classificationLevel);
        out.put(protectionAuthorityFlags.array());
    }

    @Override
    public int length() {
        return 3 + protectionAuthorityFlags.length();
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.SECURITY;
    }

    public static Security decode(ByteBuffer in){
        byte classificationLevel = in.get();
        byte[] protectionAuthorityFlags = new byte[in.remaining()];
        in.get(protectionAuthorityFlags);
        return new Security(classificationLevel, protectionAuthorityFlags);
    }
}
