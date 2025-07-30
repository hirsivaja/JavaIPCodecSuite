package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpAddress;
import com.github.hirsivaja.ip.IpUtils;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class Ipv6Address implements IpAddress {
    public static final int IPV6_ADDRESS_LEN = 16;
    private final byte[] addressBytes;

    public Ipv6Address(byte[] addressBytes) {
        if(addressBytes.length != IPV6_ADDRESS_LEN) {
            throw new IllegalArgumentException("Incorrect length for IPv6 address " + addressBytes.length);
        }
        this.addressBytes = addressBytes;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(addressBytes);
    }

    @Override
    public int getLength() {
        return IPV6_ADDRESS_LEN;
    }

    @Override
    public byte[] getAddress() {
        return addressBytes;
    }

    @Override
    public InetAddress toInetAddress() {
        try {
            return InetAddress.getByAddress(addressBytes);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Not a valid IPv6 address!", e);
        }
    }

    public Inet6Address toInet6Address() {
        return (Inet6Address) toInetAddress();
    }

    public static Ipv6Address decode(ByteBuffer in) {
        if(in.remaining() < IPV6_ADDRESS_LEN) {
            throw new IllegalArgumentException("Too few remaining bytes " + in.remaining());
        }
        byte[] addressBytes = new byte[IPV6_ADDRESS_LEN];
        in.get(addressBytes);
        return new Ipv6Address(addressBytes);
    }

    @Override
    public String toString() {
        try {
            return this.getClass().getSimpleName() + "(" + toInetAddress().getHostAddress() + ")";
        } catch (IllegalArgumentException ignored) {
            // Suppressing the exception
        }
        return this.getClass().getSimpleName() + "(" + IpUtils.printHexBinary(addressBytes) + ")";
    }
}
