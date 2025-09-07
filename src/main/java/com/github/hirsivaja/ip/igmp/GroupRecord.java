package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record GroupRecord(
        byte recordType,
        Ipv4Address multicastAddress,
        List<Ipv4Address> sourceAddresses,
        ByteArray auxData) {

    public GroupRecord(byte recordType, Ipv4Address multicastAddress, List<Ipv4Address> sourceAddresses, byte[] auxData) {
        this(recordType, multicastAddress, sourceAddresses, new ByteArray(auxData));
    }

    public void encode(ByteBuffer out) {
        out.put(recordType);
        out.put((byte) auxData.length());
        out.putShort((short) sourceAddresses.size());
        multicastAddress.encode(out);
        for(Ipv4Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
        out.put(auxData.array());
    }

    public int length() {
        return 8 + (sourceAddresses.size() * 4) + auxData.length();
    }

    public static GroupRecord decode(ByteBuffer in) {
        byte recordType = in.get();
        int auxDataLen = in.get() & 0xFF;
        short numberOfSources = in.getShort();
        Ipv4Address multicastAddress = Ipv4Address.decode(in);
        List<Ipv4Address> sourceAddresses = new ArrayList<>();
        for(int i = 0; i < numberOfSources; i++) {
            sourceAddresses.add(Ipv4Address.decode(in));
        }
        byte[] auxData = new byte[auxDataLen];
        in.get(auxData);
        return new GroupRecord(recordType, multicastAddress, sourceAddresses, auxData);
    }

    public byte[] rawAuxData() {
        return auxData.array();
    }
}
