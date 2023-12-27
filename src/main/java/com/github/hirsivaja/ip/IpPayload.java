package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;
import java.util.Arrays;

public interface IpPayload {
    void encode(ByteBuffer out);
    int getLength();
    IpHeader getHeader();

    default byte[] toBytes() {
        ByteBuffer out = ByteBuffer.allocate(getLength());
        encode(out);
        return Arrays.copyOfRange(out.array(), 0, out.rewind().remaining());
    }

    static IpPayload fromBytes(byte[] ipPayload) {
        return decode(ByteBuffer.wrap(ipPayload));
    }

    static IpPayload decode(ByteBuffer in) {
        byte version = (byte) (in.get() >>> Ipv4Header.VERSION_SHIFT);
        in.rewind();
        if(version == Ipv4Header.VERSION) {
            return Ipv4Payload.decode(in);
        } else if (version == Ipv6Header.VERSION) {
            return Ipv6Payload.decode(in);
        } else {
            throw new IllegalArgumentException("Not an IP payload");
        }
    }
}
