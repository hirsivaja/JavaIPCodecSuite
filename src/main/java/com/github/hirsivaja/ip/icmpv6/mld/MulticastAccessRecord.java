package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public class MulticastAccessRecord {
    private final byte recordType;
    private final Ipv6Address multicastAddress;
    private final Ipv6Address[] sourceAddresses;
    private final byte[] auxData;

    public MulticastAccessRecord(byte recordType, Ipv6Address multicastAddress, Ipv6Address[] sourceAddresses, byte[] auxData) {
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
        for(Ipv6Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
        out.put(auxData);
    }

    public int getLength() {
        return 20 + (sourceAddresses.length * 16) + auxData.length ;
    }

    public static MulticastAccessRecord decode(ByteBuffer in) {
        byte recordType = in.get();
        int auxDataLen = in.get() & 0xFF;
        short numberOfSources = in.getShort();
        Ipv6Address multicastAddress = Ipv6Address.decode(in);
        Ipv6Address[] sourceAddresses = new Ipv6Address[numberOfSources];
        for(int i = 0; i < sourceAddresses.length; i++) {
            sourceAddresses[i] = Ipv6Address.decode(in);
        }
        byte[] auxData = new byte[auxDataLen];
        in.get(auxData);
        return new MulticastAccessRecord(recordType, multicastAddress, sourceAddresses, auxData);
    }

    public byte getRecordType() {
        return recordType;
    }

    public Ipv6Address getMulticastAddress() {
        return multicastAddress;
    }

    public Ipv6Address[] getSourceAddresses() {
        return sourceAddresses;
    }

    public byte[] getAuxData() {
        return auxData;
    }
}
