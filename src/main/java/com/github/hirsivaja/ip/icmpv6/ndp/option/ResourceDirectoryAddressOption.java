package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;

public record ResourceDirectoryAddressOption(int validLifetime, Ipv6Address rdAddress) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0); // RESERVED
        out.putInt(validLifetime);
        rdAddress.encode(out);
    }

    @Override
    public int length() {
        return 24;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.RESOURCE_DIRECTORY_ADDRESS;
    }

    public static ResourceDirectoryAddressOption decode(ByteBuffer in){
        in.getShort(); // RESERVED
        int validLifetime = in.getInt();
        Ipv6Address rdAddress = Ipv6Address.decode(in);
        return new ResourceDirectoryAddressOption(validLifetime, rdAddress);
    }
}
