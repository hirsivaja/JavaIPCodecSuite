package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpAddress;
import com.github.hirsivaja.ip.IpUtils;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public record Ipv4Address(ByteArray address) implements IpAddress {
    public static final int IPV4_ADDRESS_LEN = 4;

    public Ipv4Address {
        if(address.array().length != IPV4_ADDRESS_LEN) {
            throw new IllegalArgumentException("Incorrect length for IPv4 address " + address.array().length);
        }
    }

    public Ipv4Address(byte[] addressBytes) {
        this(new ByteArray(addressBytes));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(address.array());
    }

    @Override
    public int length() {
        return IPV4_ADDRESS_LEN;
    }

    @Override
    public byte[] rawAddress() {
        return address.array();
    }

    @Override
    public InetAddress toInetAddress() {
        try {
            return InetAddress.getByAddress(address.array());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Not a valid IPv4 address!", e);
        }
    }

    public Inet4Address toInet4Address() {
        return (Inet4Address) toInetAddress();
    }

    public int toInt() {
        return ByteBuffer.wrap(address.array()).getInt();
    }

    public static Ipv4Address decode(ByteBuffer in) {
        if(in.remaining() < IPV4_ADDRESS_LEN) {
            throw new IllegalArgumentException("Too few remaining bytes " + in.remaining());
        }
        byte[] addressBytes = new byte[IPV4_ADDRESS_LEN];
        in.get(addressBytes);
        return new Ipv4Address(addressBytes);
    }

    @Override
    public String toString() {
        try {
            return this.getClass().getSimpleName() + "[" + toInetAddress().getHostAddress() + "]";
        } catch (IllegalArgumentException _) {
            // Suppressing the exception
        }
        return this.getClass().getSimpleName() + "[" + IpUtils.printHexBinary(address.array()) + "]";
    }
}
