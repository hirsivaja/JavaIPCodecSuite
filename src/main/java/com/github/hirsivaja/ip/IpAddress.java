package com.github.hirsivaja.ip;

import java.net.InetAddress;
import java.nio.ByteBuffer;

public interface IpAddress {
    void encode(ByteBuffer out);
    int getLength();
    byte[] getAddress();
    InetAddress toInetAddress();
}
