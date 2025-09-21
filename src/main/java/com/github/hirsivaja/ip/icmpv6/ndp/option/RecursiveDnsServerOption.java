package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RecursiveDnsServerOption(int lifetime, List<Ipv6Address> addresses) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0); // RESERVED
        out.putInt(lifetime);
        addresses.forEach(address -> address.encode(out));
    }

    @Override
    public int length() {
        return 8 + addresses.size() * 16;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.RECURSIVE_DNS_SERVER;
    }

    public static RecursiveDnsServerOption decode(ByteBuffer in){
        in.getShort(); // RESERVED
        int lifetime = in.getInt();
        List<Ipv6Address> addresses = new ArrayList<>();
        while(in.hasRemaining()){
            addresses.add(Ipv6Address.decode(in));
        }
        return new RecursiveDnsServerOption(lifetime, addresses);
    }
}
