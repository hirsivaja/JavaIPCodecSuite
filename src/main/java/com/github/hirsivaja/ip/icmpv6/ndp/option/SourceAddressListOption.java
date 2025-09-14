package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record SourceAddressListOption(List<Ipv6Address> sourceAddresses) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) ((sourceAddresses.size() * 2) + 1));
        out.putShort((short) 0);
        out.putInt(0);
        sourceAddresses.forEach(sourceAddress -> sourceAddress.encode(out));
    }

    @Override
    public int length() {
        return sourceAddresses.size() * 16 + 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.SOURCE_ADDRESS_LIST;
    }

    public static SourceAddressListOption decode(ByteBuffer in){
        byte len = in.get();
        in.getShort(); // RESERVED
        in.getInt(); // RESERVED
        List<Ipv6Address> sourceAddresses = new ArrayList<>();
        for(int i = 0; i < (len - 1) / 2; i++) {
            sourceAddresses.add(Ipv6Address.decode(in));
        }
        return new SourceAddressListOption(sourceAddresses);
    }
}
