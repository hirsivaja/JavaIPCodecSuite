package com.github.hirsivaja.ip.ipv6.extension.mobility;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record BindingAuthorizationData(ByteArray authenticator) implements MobilityOption {

    public BindingAuthorizationData(byte[] authenticator) {
        this(new ByteArray(authenticator));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(authenticator.array());
    }

    @Override
    public int length() {
        return 2 + authenticator.length();
    }

    @Override
    public MobilityOptionType optionType() {
        return MobilityOptionType.BINDING_AUTHORIZATION_DATA;
    }

    public static MobilityOption decode(ByteBuffer in) {
        byte[] authenticator = new byte[in.remaining()];
        in.get(authenticator);
        return new BindingAuthorizationData(authenticator);
    }
}
