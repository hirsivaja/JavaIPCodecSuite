package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record TargetAddressListOption(List<Ipv6Address> targetAddresses) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) ((targetAddresses.size() * 2) + 1));
        out.putShort((short) 0);
        out.putInt(0);
        targetAddresses.forEach(targetAddress -> targetAddress.encode(out));
    }

    @Override
    public int length() {
        return targetAddresses.size() * 16 + 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.TARGET_ADDRESS_LIST;
    }

    public static TargetAddressListOption decode(ByteBuffer in){
        byte len = in.get();
        in.getShort(); // RESERVED
        in.getInt(); // RESERVED
        List<Ipv6Address> targetAddresses = new ArrayList<>();
        for(int i = 0; i < (len - 1) / 2; i++) {
            targetAddresses.add(Ipv6Address.decode(in));
        }
        return new TargetAddressListOption(targetAddresses);
    }
}
