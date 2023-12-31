package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public class GroupRecord {
    private final byte recordType;
    private final int multicastAddress;
    private final int[] sourceAddresses;
    private final byte[] auxData;

    public GroupRecord(byte recordType, int multicastAddress, int[] sourceAddresses, byte[] auxData) {
        this.recordType = recordType;
        this.multicastAddress = multicastAddress;
        this.sourceAddresses = sourceAddresses;
        this.auxData = auxData;
    }

    public void encode(ByteBuffer out) {
        out.put(recordType);
        out.put((byte) auxData.length);
        out.putShort((short) sourceAddresses.length);
        out.putInt(multicastAddress);
        for(int sourceAddress : sourceAddresses) {
            out.putInt(sourceAddress);
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
        int multicastAddress = in.getInt();
        int[] sourceAddresses = new int[numberOfSources];
        for(int i = 0; i < sourceAddresses.length; i++) {
            sourceAddresses[i] = in.getInt();
        }
        byte[] auxData = new byte[auxDataLen];
        in.get(auxData);
        return new GroupRecord(recordType, multicastAddress, sourceAddresses, auxData);
    }

    public byte getRecordType() {
        return recordType;
    }

    public int getMulticastAddress() {
        return multicastAddress;
    }

    public int[] getSourceAddresses() {
        return sourceAddresses;
    }

    public byte[] getAuxData() {
        return auxData;
    }
}
