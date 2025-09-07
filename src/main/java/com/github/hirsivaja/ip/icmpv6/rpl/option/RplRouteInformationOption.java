package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record RplRouteInformationOption(
        byte prefixLen,
        byte preference,
        int routeLifetime,
        ByteArray prefix) implements RplOption {

    public RplRouteInformationOption(byte prefixLen, byte preference, int routeLifetime, byte[] prefix) {
        this(prefixLen, preference, routeLifetime, new ByteArray(prefix));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (6 + prefix.length()));
        out.put(prefixLen);
        out.put(preference);
        out.putInt(routeLifetime);
        out.put(prefix.array());
    }

    @Override
    public int length() {
        return 8 + prefix.length();
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.ROUTE_INFORMATION;
    }

    public static RplRouteInformationOption decode(ByteBuffer in){
        byte len = in.get();
        byte prefixLen = in.get();
        byte preference = in.get();
        int routeLifetime = in.getInt();
        byte[] prefix = new byte[len - 6];
        in.get(prefix);
        return new RplRouteInformationOption(prefixLen, preference, routeLifetime, prefix);
    }

    public byte[] rawPrefix() {
        return prefix.array();
    }
}
