package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public record RplPadOption() implements RplOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
    }

    @Override
    public int length() {
        return 1;
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.PAD_1;
    }

    public static RplPadOption decode(){
        return new RplPadOption();
    }
}
