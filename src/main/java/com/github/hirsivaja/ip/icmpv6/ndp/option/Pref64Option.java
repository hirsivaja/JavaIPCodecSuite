package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record Pref64Option(short scaledLifetime, byte plc, ByteArray highestPrefixBits) implements NdpOption {

    public Pref64Option(short scaledLifetime, byte plc, byte[] highestPrefixBits) {
        this(scaledLifetime, plc, new ByteArray(highestPrefixBits));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        short scaledLifetimeAndPlc = (short) ((scaledLifetime << 3) | plc);
        out.putShort(scaledLifetimeAndPlc);
        out.put(highestPrefixBits.array());
    }

    @Override
    public int length() {
        return 16;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.PREF64;
    }

    public static Pref64Option decode(ByteBuffer in){
        short scaledLifetimeAndPlc = in.getShort();
        short scaledLifetime = (short) ((scaledLifetimeAndPlc >> 3) & 0x1FFF);
        byte plc = (byte) (scaledLifetimeAndPlc & 0x07);
        byte[] highestPrefixBits = new byte[12];
        in.get(highestPrefixBits);
        return new Pref64Option(scaledLifetime, plc, highestPrefixBits);
    }
}
