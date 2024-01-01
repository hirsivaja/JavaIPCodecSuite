package com.github.hirsivaja.ip.ethernet;

import java.nio.ByteBuffer;

public class MacAddress {
    private static final byte MAC_ADDRESS_LEN = 6;
    private final byte[] macAddressBytes;

    public MacAddress(byte[] macAddress) {
        this.macAddressBytes = macAddress;
    }

    public void encode(ByteBuffer out) {
        out.put(macAddressBytes);
    }

    public int getLength() {
        return MAC_ADDRESS_LEN;
    }

    public static MacAddress decode(ByteBuffer in) {
        byte[] macAddress = new byte[MAC_ADDRESS_LEN];
        in.get(macAddress);
        return new MacAddress(macAddress);
    }

    public byte[] getBytes() {
        return macAddressBytes;
    }
}
