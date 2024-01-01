package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public class RplPrefixInformationOption implements RplOption {
    private static final int LEN = 30;
    private final byte prefixLen;
    private final byte flags;
    private final int validLifetime;
    private final int preferredLifetime;
    private final Ipv6Address prefix;

    public RplPrefixInformationOption(byte prefixLen, byte flags, int validLifetime, int preferredLifetime, Ipv6Address prefix) {
        this.prefixLen = prefixLen;
        this.flags = flags;
        this.validLifetime = validLifetime;
        this.preferredLifetime = preferredLifetime;
        this.prefix = prefix;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) LEN);
        out.put(prefixLen);
        out.put(flags);
        out.putInt(validLifetime);
        out.putInt(preferredLifetime);
        out.putInt(0); // RESERVED
        prefix.encode(out);
    }

    @Override
    public int getLength() {
        return 32;
    }

    @Override
    public RplOptionType getOptionType() {
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

    public byte getPrefixLen() {
        return prefixLen;
    }

    public byte getFlags() {
        return flags;
    }

    public int getValidLifetime() {
        return validLifetime;
    }

    public int getPreferredLifetime() {
        return preferredLifetime;
    }

    public Ipv6Address getPrefix() {
        return prefix;
    }
}
