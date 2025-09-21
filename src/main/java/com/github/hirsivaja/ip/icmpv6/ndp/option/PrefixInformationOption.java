package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public record PrefixInformationOption(
        byte prefixLen,
        byte flags,
        int validLifetime,
        int preferredLifetime,
        Ipv6Address prefix) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(prefixLen);
        out.put(flags);
        out.putInt(validLifetime);
        out.putInt(preferredLifetime);
        out.putInt(0); // RESERVED
        prefix.encode(out);
    }

    @Override
    public int length() {
        return 32;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.PREFIX_INFORMATION;
    }

    public static PrefixInformationOption decode(ByteBuffer in){
        byte prefixLen = in.get();
        byte flags = in.get();
        int validLifetime = in.getInt();
        int preferredLifetime = in.getInt();
        in.getInt(); // RESERVED
        Ipv6Address prefix = Ipv6Address.decode(in);
        return new PrefixInformationOption(prefixLen, flags, validLifetime, preferredLifetime, prefix);
    }
}
