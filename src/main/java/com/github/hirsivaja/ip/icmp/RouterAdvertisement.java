package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RouterAdvertisement(short lifetime, List<Ipv4Address> addresses, List<Integer> preferenceLevels) implements IcmpMessage {
    private static final byte ADDRESS_ENTRY_SIZE = 2;
    @Override
    public void encode(ByteBuffer out) {
        out.put((byte) addresses.size());
        out.put(ADDRESS_ENTRY_SIZE);
        out.putShort(lifetime);
        for(int i = 0; i < addresses.size(); i++) {
            addresses.get(i).encode(out);
            out.putInt(preferenceLevels.get(i));
        }
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + addresses.size() * ADDRESS_ENTRY_SIZE * 4;
    }

    public static IcmpMessage decode(ByteBuffer in) {
        byte numberOfAddresses = in.get();
        byte addressEntrySize = in.get();
        short lifetime = in.getShort();
        if(addressEntrySize != ADDRESS_ENTRY_SIZE) {
            throw new IllegalArgumentException("Unexpected Address Entry size " + addressEntrySize);
        }
        List<Ipv4Address> addresses = new ArrayList<>();
        List<Integer> preferenceLevels = new ArrayList<>();
        for(int i = 0; i < numberOfAddresses; i++) {
            addresses.add(Ipv4Address.decode(in));
            preferenceLevels.add(in.getInt());
        }
        return new RouterAdvertisement(lifetime, addresses, preferenceLevels);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.ROUTER_ADVERTISEMENT;
    }

    @Override
    public IcmpCode code() {
        return IcmpCodes.ROUTER_ADVERTISEMENT;
    }
}
