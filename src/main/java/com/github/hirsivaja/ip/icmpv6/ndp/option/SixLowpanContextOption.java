package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record SixLowpanContextOption(byte flags, short validLifetime, ByteArray contextPrefix) implements NdpOption {

    public SixLowpanContextOption(byte flags, short validLifetime, byte[] contextPrefix) {
        this(flags, validLifetime, new ByteArray(contextPrefix));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put((byte) (contextPrefix.length() * 8));
        out.put(flags);
        out.putShort((short) 0); // RESERVED
        out.putShort(validLifetime);
        out.put(contextPrefix.array());
        out.put(new byte[paddingLen()]);
    }

    @Override
    public int length() {
        return 8 + contextPrefix.length() + paddingLen();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.SIXLOWPAN_CONTEXT;
    }

    public static SixLowpanContextOption decode(ByteBuffer in){
        byte contextLen = in.get();
        byte flags = in.get();
        in.getShort(); // RESERVED
        short validLifetime = in.getShort();
        byte[] contextPrefix = new byte[contextLen / 8];
        in.get(contextPrefix);
        byte[] padding = new byte[in.remaining()];
        in.get(padding);
        return new SixLowpanContextOption(flags, validLifetime, contextPrefix);
    }

    private byte paddingLen() {
        return (byte) (8 - ((8 + contextPrefix.length()) % 8));
    }
}
