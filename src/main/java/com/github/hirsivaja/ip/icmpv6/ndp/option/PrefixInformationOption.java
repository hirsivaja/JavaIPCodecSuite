package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public class PrefixInformationOption implements NdpOption {
    private final byte prefixLen;
    private final byte flags;
    private final int validLifetime;
    private final int preferredLifetime;
    private final Ipv6Address prefix;

    public PrefixInformationOption(byte prefixLen, byte flags, int validLifetime, int preferredLifetime, Ipv6Address prefix) {
        this.prefixLen = prefixLen;
        this.flags = flags;
        this.validLifetime = validLifetime;
        this.preferredLifetime = preferredLifetime;
        this.prefix = prefix;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) 4);
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
    public NdpOptionType getOptionType() {
        return NdpOptionType.PREFIX_INFORMATION;
    }

    public static PrefixInformationOption decode(ByteBuffer in){
        in.get(); // Length
        byte prefixLen = in.get();
        byte flags = in.get();
        int validLifetime = in.getInt();
        int preferredLifetime = in.getInt();
        in.getInt(); // RESERVED
        Ipv6Address prefix = Ipv6Address.decode(in);
        return new PrefixInformationOption(prefixLen, flags, validLifetime, preferredLifetime, prefix);
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
