package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record HomeAgentAddressDiscoveryReply(short identifier, List<Ipv6Address> homeAgentAddresses)  implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        out.putShort((short) 0); // RESERVED
        homeAgentAddresses.forEach(homeAgentAddress -> homeAgentAddress.encode(out));
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + homeAgentAddresses.stream().mapToInt(Ipv6Address::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        short identifier = in.getShort();
        in.getShort(); // RESERVED
        List<Ipv6Address> homeAgentAddresses = new ArrayList<>();
        while(in.hasRemaining()) {
            homeAgentAddresses.add(Ipv6Address.decode(in));
        }
        return new HomeAgentAddressDiscoveryReply(identifier, homeAgentAddresses);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.HOME_AGENT_ADDRESS_DISCOVERY_REPLY;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE;
    }
}
