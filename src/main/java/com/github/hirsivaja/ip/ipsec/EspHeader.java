package com.github.hirsivaja.ip.ipsec;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.IpProtocols;
import com.github.hirsivaja.ip.ipv6.extension.ExtensionHeader;

import java.nio.ByteBuffer;

public record EspHeader(int spi, int seqNumber, ByteArray data) implements ExtensionHeader {

    public EspHeader(int spi, int seqNumber, byte[] data) {
        this(spi, seqNumber, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(spi);
        out.putInt(seqNumber);
        out.put(data.array());
    }

    @Override
    public int length() {
        return 8 + data.length();
    }

    @Override
    public IpProtocol nextHeader() {
        return IpProtocols.IPV6_NO_NEXT;
    }

    public static EspHeader decode(ByteBuffer in) {
        int spi = in.getInt();
        int seqNumber = in.getInt();
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new EspHeader(spi, seqNumber, data);
    }

    public byte[] rawData() {
        return data.array();
    }
}
