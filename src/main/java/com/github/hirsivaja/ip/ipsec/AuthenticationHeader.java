package com.github.hirsivaja.ip.ipsec;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public record AuthenticationHeader(IpProtocol nextHeader, int spi, int seqNumber, ByteArray icv) {

    public AuthenticationHeader(IpProtocol nextHeader, int spi, int seqNumber, byte[] icv) {
        this(nextHeader, spi, seqNumber, new ByteArray(icv));
    }

    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) (icv.length() / 4 + 1));
        out.putShort((short) 0);
        out.putInt(spi);
        out.putInt(seqNumber);
        out.put(icv.array());
    }

    public int length() {
        return 12 + icv.length();
    }

    public static AuthenticationHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        int payloadLen = Byte.toUnsignedInt(in.get()) * 4;
        in.getShort(); // RESERVED
        int spi = in.getInt();
        int seqNumber = in.getInt();
        byte[] icv = new byte[payloadLen - 4];
        in.get(icv);
        return new AuthenticationHeader(nextHeader, spi, seqNumber, icv);
    }

    public byte[] rawIcv() {
        return icv.array();
    }
}
