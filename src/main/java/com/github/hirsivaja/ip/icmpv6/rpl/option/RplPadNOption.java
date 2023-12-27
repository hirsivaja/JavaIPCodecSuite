package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplPadNOption implements RplOption {

    private final byte len;

    public RplPadNOption(byte len) {
        this.len = len;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put(len);
        out.put(new byte[len]);
    }

    @Override
    public int getLength() {
        return 2 + len;
    }

    @Override
    public RplOptionType getOptionType() {
        return RplOptionType.PAD_N;
    }

    public static RplPadNOption decode(ByteBuffer in){
        byte len = in.get();
        in.get(len); // PADDING
        return new RplPadNOption(len);
    }
}
