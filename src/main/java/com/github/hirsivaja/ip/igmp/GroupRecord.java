package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public class GroupRecord {
    private final byte recordType;
    private final Ipv4Address multicastAddress;
    private final Ipv4Address[] sourceAddresses;
    private final byte[] auxData;

    public GroupRecord(byte recordType, Ipv4Address multicastAddress, Ipv4Address[] sourceAddresses, byte[] auxData) {
        this.recordType = recordType;
        this.multicastAddress = multicastAddress;
        this.sourceAddresses = sourceAddresses;
        this.auxData = auxData;
    }

    public void encode(ByteBuffer out) {
        out.put(recordType);
        out.put((byte) auxData.length);
        out.putShort((short) sourceAddresses.length);
        multicastAddress.encode(out);
        for(Ipv4Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
        out.put(auxData);
    }

    public int getLength() {
        return 8 + (sourceAddresses.length * 4) + auxData.length ;
    }

    public static GroupRecord decode(ByteBuffer in) {
        byte recordType = in.get();
        int auxDataLen = in.get() & 0xFF;
        short numberOfSources = in.getShort();
        Ipv4Address multicastAddress = Ipv4Address.decode(in);
        Ipv4Address[] sourceAddresses = new Ipv4Address[numberOfSources];
        for(int i = 0; i < sourceAddresses.length; i++) {
            sourceAddresses[i] = Ipv4Address.decode(in);
        }
        byte[] auxData = new byte[auxDataLen];
        in.get(auxData);
        return new GroupRecord(recordType, multicastAddress, sourceAddresses, auxData);
    }

    public byte getRecordType() {
        return recordType;
    }

    public Ipv4Address getMulticastAddress() {
        return multicastAddress;
    }

    public Ipv4Address[] getSourceAddresses() {
        return sourceAddresses;
    }

    public byte[] getAuxData() {
        return auxData;
    }
}
