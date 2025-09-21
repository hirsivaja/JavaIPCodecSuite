package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record IpAddressOrPrefixOption(byte optionCode, byte prefixLen, Ipv6Address prefix) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(optionCode);
        out.put(prefixLen);
        out.putInt(0); // RESERVED
        prefix.encode(out);
    }

    @Override
    public int length() {
        return 24;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.IP_ADDRESS_OR_PREFIX;
    }

    public static IpAddressOrPrefixOption decode(ByteBuffer in){
        byte optionCode = in.get();
        byte prefixLen = in.get();
        in.getInt(); // RESERVED
        Ipv6Address prefix = Ipv6Address.decode(in);
        return new IpAddressOrPrefixOption(optionCode, prefixLen, prefix);
    }
}
