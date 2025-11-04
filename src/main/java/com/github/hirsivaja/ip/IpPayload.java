package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public sealed interface IpPayload permits Ipv4Payload, Ipv6Payload {
    void encode(ByteBuffer out);
    int length();
}
