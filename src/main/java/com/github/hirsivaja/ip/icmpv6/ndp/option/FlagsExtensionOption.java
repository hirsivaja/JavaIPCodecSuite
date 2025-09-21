package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record FlagsExtensionOption(ByteArray flags) implements NdpOption {

    public FlagsExtensionOption(byte[] flags) {
        this(new ByteArray(flags));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(flags.array());
    }

    @Override
    public int length() {
        return 2 + flags.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.RA_FLAGS_EXTENSION;
    }

    public static FlagsExtensionOption decode(ByteBuffer in){
        byte[] flags = new byte[in.remaining()];
        in.get(flags);
        return new FlagsExtensionOption(flags);
    }
}
