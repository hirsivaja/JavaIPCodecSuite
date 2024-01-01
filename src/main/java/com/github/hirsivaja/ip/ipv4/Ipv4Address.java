package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class Ipv4Address implements IpAddress {
    public static final int IPV4_ADDRESS_LEN = 4;
    private final byte[] addressBytes;

    public Ipv4Address(byte[] addressBytes) {
        if(addressBytes.length != IPV4_ADDRESS_LEN) {
            throw new IllegalArgumentException("Incorrect length for IPv4 address " + addressBytes.length);
        }
        this.addressBytes = addressBytes;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(addressBytes);
    }

    @Override
    public int getLength() {
        return IPV4_ADDRESS_LEN;
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
            throw new IllegalArgumentException("Not a valid IPv4 address!", e);
        }
    }

    public Inet4Address toInet4Address() {
        return (Inet4Address) toInetAddress();
    }

    public int toInt() {
        return ByteBuffer.wrap(addressBytes).getInt();
    }

    public static Ipv4Address decode(ByteBuffer in) {
        if(in.remaining() < IPV4_ADDRESS_LEN) {
            throw new IllegalArgumentException("Too few remaining bytes " + in.remaining());
        }
        byte[] addressBytes = new byte[IPV4_ADDRESS_LEN];
        in.get(addressBytes);
        return new Ipv4Address(addressBytes);
    }
}
