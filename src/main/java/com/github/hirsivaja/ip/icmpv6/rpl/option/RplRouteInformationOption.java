package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplRouteInformationOption implements RplOption {

    private final byte prefixLen;
    private final byte preference;
    private final int routeLifetime;
    private final byte[] prefix;

    public RplRouteInformationOption(byte prefixLen, byte preference, int routeLifetime, byte[] prefix) {
        this.prefixLen = prefixLen;
        this.preference = preference;
        this.routeLifetime = routeLifetime;
        this.prefix = prefix;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) (6 + prefix.length));
        out.put(prefixLen);
        out.put(preference);
        out.putInt(routeLifetime);
        out.put(prefix);
    }

    @Override
    public int getLength() {
        return 8 + prefix.length;
    }

    @Override
    public RplOptionType getOptionType() {
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

    public byte getPrefixLen() {
        return prefixLen;
    }

    public byte getPreference() {
        return preference;
    }

    public int getRouteLifetime() {
        return routeLifetime;
    }

    public byte[] getPrefix() {
        return prefix;
    }
}
