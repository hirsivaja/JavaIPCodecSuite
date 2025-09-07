package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record RplTargetOption(
        byte flags,
        byte prefixLen,
        ByteArray prefix) implements RplOption {

    public RplTargetOption(byte flags, byte prefixLen, byte[] prefix) {
        this(flags, prefixLen, new ByteArray(prefix));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (2 + prefix.length()));
        out.put(flags);
        out.put(prefixLen);
        out.put(prefix.array());
    }

    @Override
    public int length() {
        return 4 + prefix.length();
    }

    @Override
    public RplOptionType optionType() {
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

    public byte[] rawPrefix() {
        return prefix.array();
    }
}
