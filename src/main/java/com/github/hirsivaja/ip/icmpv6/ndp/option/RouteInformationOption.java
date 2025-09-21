package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record RouteInformationOption(byte prefixLength, byte flags, int routeLifetime, ByteArray prefix) implements NdpOption {

    public RouteInformationOption(byte prefixLength, byte flags, int routeLifetime, byte[] prefix) {
        this(prefixLength, flags, routeLifetime, new ByteArray(prefix));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(prefixLength);
        out.put(flags);
        out.putInt(routeLifetime);
        out.put(prefix.array());
    }

    @Override
    public int length() {
        return 8 + prefix.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.ROUTE_INFORMATION;
    }

    public static RouteInformationOption decode(ByteBuffer in){
        byte prefixLength = in.get();
        byte flags = in.get();
        int routeLifetime = in.getInt();
        byte[] prefix = new byte[in.remaining()];
        in.get(prefix);
        return new RouteInformationOption(prefixLength, flags, routeLifetime, prefix);
    }
}
