package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record HomeAgentInformationOption(short homeAgentPreference, short homeAgentLifetime) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
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
        in.getShort(); // RESERVED
        short homeAgentPreference = in.getShort();
        short homeAgentLifetime = in.getShort();
        return new HomeAgentInformationOption(homeAgentPreference, homeAgentLifetime);
    }
}
