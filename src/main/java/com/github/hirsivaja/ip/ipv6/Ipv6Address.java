package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpAddress;
import com.github.hirsivaja.ip.IpUtils;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public record Ipv6Address(ByteArray address) implements IpAddress {
    public static final int IPV6_ADDRESS_LEN = 16;

    public Ipv6Address {
        if(address.array().length != IPV6_ADDRESS_LEN) {
            throw new IllegalArgumentException("Incorrect length for IPv6 address " + address.array().length);
        }
    }

    public Ipv6Address(byte[] addressBytes) {
        this(new ByteArray(addressBytes));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(address.array());
    }

    @Override
    public int length() {
        return IPV6_ADDRESS_LEN;
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
            return this.getClass().getSimpleName() + "[" + toInetAddress().getHostAddress() + "]";
        } catch (IllegalArgumentException _) {
            // Suppressing the exception
        }
        return this.getClass().getSimpleName() + "[" + IpUtils.printHexBinary(address.array()) + "]";
    }
}
