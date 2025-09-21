package com.github.hirsivaja.ip.ipv6.extension.mobility;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record AlternateCareOfAddress(Ipv6Address alternateCareOfAddress) implements MobilityOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        alternateCareOfAddress.encode(out);
    }

    @Override
    public int length() {
        return 18;
    }

    @Override
    public MobilityOptionType optionType() {
        return MobilityOptionType.ALTERNATE_CARE_OF_ADDRESS;
    }

    public static MobilityOption decode(ByteBuffer in) {
        Ipv6Address alternateCareOfAddress = Ipv6Address.decode(in);
        return new AlternateCareOfAddress(alternateCareOfAddress);
    }
}
