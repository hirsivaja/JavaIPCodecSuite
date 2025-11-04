package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record DuplicateAddressRequest(byte status, short registrationLifetime, long eui64, Ipv6Address registeredAddress) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.put(status);
        out.put((byte) 0); // RESERVED
        out.putShort(registrationLifetime);
        out.putLong(eui64);
        registeredAddress.encode(out);
    }

    @Override
    public int length() {
        return 28;
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        byte status = in.get();
        in.get(); // RESERVED
        short registrationLifetime = in.getShort();
        long eui64 = in.getLong();
        Ipv6Address registeredAddress = Ipv6Address.decode(in);
        return new DuplicateAddressRequest(status, registrationLifetime, eui64, registeredAddress);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.DUPLICATE_ADDRESS_REQUEST;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.DUPLICATE_ADDRESS_REQUEST;
    }
}
