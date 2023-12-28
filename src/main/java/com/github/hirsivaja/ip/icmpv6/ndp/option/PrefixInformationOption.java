package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public class PrefixInformationOption implements NdpOption {
    private final byte prefixLen;
    private final byte flags;
    private final int validLifetime;
    private final int preferredLifetime;
    private final byte[] prefix;

    public PrefixInformationOption(byte prefixLen, byte flags, int validLifetime, int preferredLifetime, byte[] prefix) {
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
        out.put(prefix);
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
        byte[] prefix = new byte[16];
        in.get(prefix);
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

    public byte[] getPrefix() {
        return prefix;
    }
}
