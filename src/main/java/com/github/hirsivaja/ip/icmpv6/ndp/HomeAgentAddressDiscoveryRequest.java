package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import java.nio.ByteBuffer;

public record HomeAgentAddressDiscoveryRequest(short identifier) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        out.putShort((short) 0); // RESERVED
    }

    @Override
    public int length() {
        return 4;
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        short identifier = in.getShort();
        in.getShort(); // RESERVED
        return new HomeAgentAddressDiscoveryRequest(identifier);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.HOME_AGENT_ADDRESS_DISCOVERY_REQUEST;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE;
    }
}
