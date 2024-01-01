package com.github.hirsivaja.ip.icmpv6.mld;

import java.nio.ByteBuffer;

public class MulticastAccessRecord {
    private final byte recordType;
    private final byte[]  multicastAddress;
    private final byte[][] sourceAddresses;
    private final byte[] auxData;

    public MulticastAccessRecord(byte recordType, byte[] multicastAddress, byte[][] sourceAddresses, byte[] auxData) {
        this.recordType = recordType;
        this.multicastAddress = multicastAddress;
        this.sourceAddresses = sourceAddresses;
        this.auxData = auxData;
    }

    public void encode(ByteBuffer out) {
        out.put(recordType);
        out.put((byte) auxData.length);
        out.putShort((short) sourceAddresses.length);
        out.put(multicastAddress);
        for(byte[] sourceAddress : sourceAddresses) {
            out.put(sourceAddress);
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
        byte[] multicastAddress = new byte[16];
        in.get(multicastAddress);
        byte[][] sourceAddresses = new byte[numberOfSources][];
        for(int i = 0; i < sourceAddresses.length; i++) {
            sourceAddresses[i] = new byte[16];
            in.get(sourceAddresses[i]);
        }
        byte[] auxData = new byte[auxDataLen];
        in.get(auxData);
        return new MulticastAccessRecord(recordType, multicastAddress, sourceAddresses, auxData);
    }

    public byte getRecordType() {
        return recordType;
    }

    public byte[] getMulticastAddress() {
        return multicastAddress;
    }

    public byte[][] getSourceAddresses() {
        return sourceAddresses;
    }

    public byte[] getAuxData() {
        return auxData;
    }
}
