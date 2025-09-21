package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record CardRequestOption(byte versionAndFlags, int sequenceNumber, ByteArray subOptions) implements NdpOption {

    public CardRequestOption(byte versionAndFlags, int sequenceNumber, byte[] subOptions) {
        this(versionAndFlags, sequenceNumber, new ByteArray(subOptions));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(versionAndFlags);
        out.put((byte) 0);
        out.putInt(sequenceNumber);
        out.put(subOptions.array());
    }

    @Override
    public int length() {
        return 8 + subOptions.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.CARD_REQUEST;
    }

    public static CardRequestOption decode(ByteBuffer in){
        byte versionAndFlags = in.get();
        in.get(); // RESERVED
        int sequenceNumber = in.getInt();
        byte[] subOptions = new byte[in.remaining()];
        in.get(subOptions);
        return new CardRequestOption(versionAndFlags, sequenceNumber, subOptions);
    }
}
