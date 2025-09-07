package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public record RplPrefixInformationOption(
        byte prefixLen,
        byte flags,
        int validLifetime,
        int preferredLifetime,
        Ipv6Address prefix) implements RplOption {
    private static final int LEN = 30;

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) LEN);
        out.put(prefixLen);
        out.put(flags);
        out.putInt(validLifetime);
        out.putInt(preferredLifetime);
        out.putInt(0); // RESERVED
        prefix.encode(out);
    }

    @Override
    public int length() {
        return 32;
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.PREFIX_INFORMATION;
    }

    public static RplPrefixInformationOption decode(ByteBuffer in){
        byte len = in.get();
        if(len != LEN){
            throw new IllegalArgumentException("Invalid length " + len);
        }
        byte prefixLen = in.get();
        byte flags = in.get();
        int validLifetime = in.getInt();
        int preferredLifetime = in.getInt();
        in.getInt(); // RESERVED
        Ipv6Address prefix = Ipv6Address.decode(in);
        return new RplPrefixInformationOption(prefixLen, flags, validLifetime, preferredLifetime, prefix);
    }
}
