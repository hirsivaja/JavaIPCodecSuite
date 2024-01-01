package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public class ArpPacket implements EthernetPayload {
    private static final short ETHERNET_TYPE = 1;
    private static final short IP_TYPE = 0x0800;
    private static final byte ETHERNET_ADDRESS_LEN = 6;
    private static final byte IP_ADDRESS_LEN = 4;
    private final short operation;
    private final MacAddress senderHwAddress;
    private final Ipv4Address senderProtocolAddress;
    private final MacAddress targetHwAddress;
    private final Ipv4Address targetProtocolAddress;

    public ArpPacket(short operation, MacAddress senderHwAddress, Ipv4Address senderProtocolAddress,
                     MacAddress targetHwAddress, Ipv4Address targetProtocolAddress) {
        this.operation = operation;
        this.senderHwAddress = senderHwAddress;
        this.senderProtocolAddress = senderProtocolAddress;
        this.targetHwAddress = targetHwAddress;
        this.targetProtocolAddress = targetProtocolAddress;
    }

    public void encode(ByteBuffer out) {
        out.putShort(ETHERNET_TYPE);
        out.putShort(IP_TYPE);
        out.put(ETHERNET_ADDRESS_LEN);
        out.put(IP_ADDRESS_LEN);
        out.putShort(operation);
        senderHwAddress.encode(out);
        senderProtocolAddress.encode(out);
        targetHwAddress.encode(out);
        targetProtocolAddress.encode(out);
    }

    public int getLength() {
        return 8 + senderHwAddress.getLength() + senderProtocolAddress.getLength() +
                targetHwAddress.getLength() + targetProtocolAddress.getLength();
    }

    public static ArpPacket decode(ByteBuffer in) {
        short hwType = in.getShort();
        if(hwType != ETHERNET_TYPE) {
            throw new IllegalArgumentException("Unknown HW type " + hwType);
        }
        short protocolType = in.getShort();
        if(protocolType != IP_TYPE) {
            throw new IllegalArgumentException("Unknown protocol type " + protocolType);
        }
        byte hwAddressLen = in.get();
        if(hwAddressLen != ETHERNET_ADDRESS_LEN) {
            throw new IllegalArgumentException("Unknown HW address len " + hwAddressLen);
        }
        byte protocolAddressLen = in.get();
        if(protocolAddressLen != IP_ADDRESS_LEN) {
            throw new IllegalArgumentException("Unknown protocol address len " + protocolAddressLen);
        }
        short operation = in.getShort();
        MacAddress senderHwAddress = MacAddress.decode(in);
        Ipv4Address senderProtocolAddress = Ipv4Address.decode(in);
        MacAddress targetHwAddress = MacAddress.decode(in);
        Ipv4Address targetProtocolAddress = Ipv4Address.decode(in);
        return new ArpPacket(operation, senderHwAddress, senderProtocolAddress, targetHwAddress, targetProtocolAddress);
    }

    public short getOperation() {
        return operation;
    }

    public MacAddress getSenderHwAddress() {
        return senderHwAddress;
    }

    public Ipv4Address getSenderProtocolAddress() {
        return senderProtocolAddress;
    }

    public MacAddress getTargetHwAddress() {
        return targetHwAddress;
    }

    public Ipv4Address getTargetProtocolAddress() {
        return targetProtocolAddress;
    }
}
