package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record ShortcutLimitOption(byte shortcutLimit) implements NdpOption {
    private final static int LEN = 1;

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) LEN);
        out.put(shortcutLimit);
        out.put((byte) 0); // RESERVED
        out.putInt(0); // RESERVED
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.SHORTCUT_LIMIT;
    }

    public static ShortcutLimitOption decode(ByteBuffer in){
        byte len = in.get();
        if(len != LEN) {
            throw new IllegalArgumentException();
        }
        byte shortcutLimit = in.get();
        in.get(); // RESERVED
        in.getInt(); // RESERVED
        return new ShortcutLimitOption(shortcutLimit);
    }
}
