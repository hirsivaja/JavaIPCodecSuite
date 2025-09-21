package com.github.hirsivaja.ip.ipv6.extension.mobility;

import java.nio.ByteBuffer;

public record BindingRefreshAdvice(short refreshInterval) implements MobilityOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.putShort(refreshInterval);
    }

    @Override
    public int length() {
        return 4;
    }

    @Override
    public MobilityOptionType optionType() {
        return MobilityOptionType.BINDING_REFRESH_ADVICE;
    }

    public static MobilityOption decode(ByteBuffer in) {
        short refreshInterval = in.getShort();
        return new BindingRefreshAdvice(refreshInterval);
    }
}
