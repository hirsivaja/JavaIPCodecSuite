package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record TunnelEncapsulationLimit(byte tunnelEncapsulationLimit) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(tunnelEncapsulationLimit);
    }

    @Override
    public int length() {
        return 3;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.TUNNEL_ENCAPSULATION_LIMIT;
    }

    public static DestinationOption decode(ByteBuffer in) {
        byte tunnelEncapsulationLimit = in.get();
        return new TunnelEncapsulationLimit(tunnelEncapsulationLimit);
    }
}
