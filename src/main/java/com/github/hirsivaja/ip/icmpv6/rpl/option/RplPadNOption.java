package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public record RplPadNOption(byte len) implements RplOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put(len);
        out.put(new byte[len]);
    }

    @Override
    public int length() {
        return 2 + len;
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.PAD_N;
    }

    public static RplPadNOption decode(ByteBuffer in){
        byte len = in.get();
        in.get(len); // PADDING
        return new RplPadNOption(len);
    }
}
