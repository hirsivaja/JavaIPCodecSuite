package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public sealed interface IpAddress permits Ipv4Address, Ipv6Address {
    void encode(ByteBuffer out);
    int length();
    byte[] rawAddress();
    InetAddress toInetAddress();
}
