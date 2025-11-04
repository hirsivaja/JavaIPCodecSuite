package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record MulticastListenerQueryMessage(
        Icmpv6Type type,
        Icmpv6Code code,
        short maximumResponseCode,
        Ipv6Address multicastAddress,
        byte flags,
        byte qqic,
        List<Ipv6Address> sourceAddresses) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(maximumResponseCode);
        out.putShort((short) 0);
        multicastAddress.encode(out);
        out.put(flags);
        out.put(qqic);
        out.putShort((short) sourceAddresses.size());
        for(Ipv6Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
    }

    @Override
    public int length() {
        return 24 + (sourceAddresses.size() * 16);
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, Icmpv6Code code) {
        short maximumResponseCode = in.getShort();
        in.getShort(); // RESERVED
        Ipv6Address multicastAddress = Ipv6Address.decode(in);
        if(in.remaining() >= 4) {
            byte flags = in.get();
            byte qqic = in.get();
            short numberOfSources = in.getShort();
            List<Ipv6Address> sourceAddresses = new ArrayList<>();
            for(int i = 0; i < numberOfSources; i++) {
                sourceAddresses.add(Ipv6Address.decode(in));
            }
            return new MulticastListenerQueryMessage(type, code, maximumResponseCode, multicastAddress, flags, qqic, sourceAddresses);
        } else {
            return new GenericMldMessage(type, code, maximumResponseCode, multicastAddress);
        }
    }
}
