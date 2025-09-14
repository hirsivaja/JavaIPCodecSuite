package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record HomeAgentInformationOption(short homeAgentPreference, short homeAgentLifetime) implements NdpOption {
    private final static int LEN = 1;

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) LEN);
        out.putShort((short) 0);
        out.putShort(homeAgentPreference);
        out.putShort(homeAgentLifetime);
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.HOME_AGENT_INFORMATION;
    }

    public static HomeAgentInformationOption decode(ByteBuffer in){
        byte len = in.get();
        if(len != LEN) {
            throw new IllegalArgumentException();
        }
        in.getShort(); // RESERVED
        short homeAgentPreference = in.getShort();
        short homeAgentLifetime = in.getShort();
        return new HomeAgentInformationOption(homeAgentPreference, homeAgentLifetime);
    }
}
