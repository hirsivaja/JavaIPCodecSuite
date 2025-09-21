package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record AuthoritativeBorderRouterOption(short versionLow, short versionHigh, short validLifetime, Ipv6Address sixlbrAddress) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort(versionLow);
        out.putShort(versionHigh);
        out.putShort(validLifetime);
        sixlbrAddress.encode(out);
    }

    @Override
    public int length() {
        return 24;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.AUTHORITATIVE_BORDER_ROUTER;
    }

    public static AuthoritativeBorderRouterOption decode(ByteBuffer in){
        short versionLow = in.getShort();
        short versionHigh = in.getShort();
        short validLifetime = in.getShort();
        Ipv6Address sixlbrAddress = Ipv6Address.decode(in);
        return new AuthoritativeBorderRouterOption(versionLow, versionHigh, validLifetime, sixlbrAddress);
    }
}
