package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record HandoverAssistInformationOption(byte optionCode, ByteArray haiValue) implements NdpOption {

    public HandoverAssistInformationOption(byte optionCode, byte[] haiValue) {
        this(optionCode, new ByteArray(haiValue));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(optionCode);
        out.put((byte) haiValue.length());
        out.put(haiValue.array());
        out.put(new byte[paddingLen()]);
    }

    @Override
    public int length() {
        return 4 + haiValue.length() + paddingLen();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.HANDOVER_ASSIST_INFORMATION;
    }

    public static HandoverAssistInformationOption decode(ByteBuffer in){
        byte optionCode = in.get();
        int haiLength = Byte.toUnsignedInt(in.get());
        byte[] haiValue = new byte[haiLength];
        in.get(haiValue);
        byte[] padding = new byte[in.remaining()];
        in.get(padding);
        return new HandoverAssistInformationOption(optionCode, haiValue);
    }

    private byte paddingLen() {
        return (byte) (8 - ((4 + haiValue.length()) % 8));
    }
}
