package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record HomeAddress(Ipv6Address homeAddress) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        homeAddress.encode(out);
    }

    @Override
    public int length() {
        return 18;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.HOME_ADDRESS;
    }

    public static DestinationOption decode(ByteBuffer in) {
        Ipv6Address homeAddress = Ipv6Address.decode(in);
        return new HomeAddress(homeAddress);
    }
}
