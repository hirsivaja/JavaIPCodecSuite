package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplPadOption implements RplOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
    }

    @Override
    public int getLength() {
        return 1;
    }

    @Override
    public RplOptionType getOptionType() {
        return RplOptionType.PAD_1;
    }

    public static RplPadOption decode(){
        return new RplPadOption();
    }
}
