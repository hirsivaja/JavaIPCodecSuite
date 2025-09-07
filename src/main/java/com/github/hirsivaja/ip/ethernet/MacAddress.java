package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpUtils;

import java.nio.ByteBuffer;

public record MacAddress(ByteArray macAddressBytes) {
    private static final byte MAC_ADDRESS_LEN = 6;

    public MacAddress(byte[] macAddress) {
        this(new ByteArray(macAddress));
    }

    public void encode(ByteBuffer out) {
        out.put(macAddressBytes.array());
    }

    public int length() {
        return MAC_ADDRESS_LEN;
    }

    public static MacAddress decode(ByteBuffer in) {
        byte[] macAddress = new byte[MAC_ADDRESS_LEN];
        in.get(macAddress);
        return new MacAddress(macAddress);
    }

    public byte[] toBytes() {
        return macAddressBytes.array();
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "[" + IpUtils.printHexBinary(macAddressBytes.array()) + "]";
    }
}
