package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public record GenericMldMessage(
        Icmpv6Type type,
        byte code,
        short maximumResponseDelay,
        Ipv6Address multicastAddress) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(maximumResponseDelay);
        out.putShort((short) 0);
        multicastAddress.encode(out);
    }

    @Override
    public int length() {
        return BASE_LEN + 20;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        short maximumResponseDelay = in.getShort();
        in.getShort(); // RESERVED
        Ipv6Address multicastAddress = Ipv6Address.decode(in);
        return new GenericMldMessage(type, code, maximumResponseDelay, multicastAddress);
    }
}
