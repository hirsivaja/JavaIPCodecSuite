package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record MulticastAccessRecord(
        byte recordType,
        Ipv6Address multicastAddress,
        List<Ipv6Address> sourceAddresses,
        ByteArray auxData) {

    public MulticastAccessRecord(byte recordType, Ipv6Address multicastAddress,
            List<Ipv6Address> sourceAddresses, byte[] auxData) {
        this(recordType, multicastAddress, sourceAddresses, new ByteArray(auxData));
    }

    public void encode(ByteBuffer out) {
        out.put(recordType);
        out.put((byte) auxData.array().length);
        out.putShort((short) sourceAddresses.size());
        multicastAddress.encode(out);
        for(Ipv6Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
        out.put(auxData.array());
    }

    public int getLength() {
        return 20 + (sourceAddresses.size() * 16) + auxData.array().length ;
    }

    public static MulticastAccessRecord decode(ByteBuffer in) {
        byte recordType = in.get();
        int auxDataLen = in.get() & 0xFF;
        short numberOfSources = in.getShort();
        Ipv6Address multicastAddress = Ipv6Address.decode(in);
        List<Ipv6Address> sourceAddresses = new ArrayList<>();
        for(int i = 0; i < numberOfSources; i++) {
            sourceAddresses.add(Ipv6Address.decode(in));
        }
        byte[] auxData = new byte[auxDataLen];
        in.get(auxData);
        return new MulticastAccessRecord(recordType, multicastAddress, sourceAddresses, auxData);
    }

    public byte[] rawAuxData() {
        return auxData.array();
    }
}
