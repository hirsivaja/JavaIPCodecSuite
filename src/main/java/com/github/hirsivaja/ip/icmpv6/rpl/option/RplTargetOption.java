package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplTargetOption implements RplOption {

    private final byte flags;
    private final byte prefixLen;
    private final byte[] prefix;

    public RplTargetOption(byte flags, byte prefixLen, byte[] prefix) {
        this.flags = flags;
        this.prefixLen = prefixLen;
        this.prefix = prefix;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) (2 + prefix.length));
        out.put(flags);
        out.put(prefixLen);
        out.put(prefix);
    }

    @Override
    public int getLength() {
        return 4 + prefix.length;
    }

    @Override
    public RplOptionType getOptionType() {
        return RplOptionType.RPL_TARGET;
    }

    public static RplTargetOption decode(ByteBuffer in){
        byte len = in.get();
        byte flags = in.get();
        byte prefixLen = in.get();
        byte[] prefix = new byte[len - 2];
        in.get(prefix);
        return new RplTargetOption(flags, prefixLen, prefix);
    }

    public byte getFlags() {
        return flags;
    }

    public byte getPrefixLen() {
        return prefixLen;
    }

    public byte[] getPrefix() {
        return prefix;
    }
}
