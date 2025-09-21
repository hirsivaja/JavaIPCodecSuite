package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record MapOption(byte flags, int validLifetime, Ipv6Address globalAddress) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(flags);
        out.put((byte) 0); // RESERVED
        out.putInt(validLifetime);
        globalAddress.encode(out);
    }

    @Override
    public int length() {
        return 24;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.MAP;
    }

    public static MapOption decode(ByteBuffer in){
        byte flags = in.get();
        in.get(); // RESERVED
        int validLifetime = in.getInt();
        Ipv6Address globalAddress = Ipv6Address.decode(in);
        return new MapOption(flags, validLifetime, globalAddress);
    }
}
