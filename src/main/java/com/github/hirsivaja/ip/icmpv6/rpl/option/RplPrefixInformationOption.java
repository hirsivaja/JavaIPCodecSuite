package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplPrefixInformationOption implements RplOption {
    private static final int LEN = 30;
    private final byte prefixLen;
    private final byte flags;
    private final int validLifetime;
    private final int preferredLifetime;
    private final byte[] prefix;

    public RplPrefixInformationOption(byte prefixLen, byte flags, int validLifetime, int preferredLifetime, byte[] prefix) {
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
        out.put(prefix);
    }

    @Override
    public int getLength() {
        return 16 + prefix.length;
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
        byte[] prefix = new byte[len - 14];
        in.get(prefix);
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

    public byte[] getPrefix() {
        return prefix;
    }
}
