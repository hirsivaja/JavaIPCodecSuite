package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import java.nio.ByteBuffer;

public sealed interface IpHeader permits Ipv4Header, Ipv6Header {
    void encode(ByteBuffer out);
    byte[] generatePseudoHeader();
    int length();
    int pseudoHeaderLength();
}
