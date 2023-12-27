package com.github.hirsivaja.ip;

import java.nio.ByteBuffer;

public interface IpHeader {
    void encode(ByteBuffer out);
    byte[] getPseudoHeader();
    int getLength();
}
