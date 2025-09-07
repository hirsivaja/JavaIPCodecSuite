package com.github.hirsivaja.ip.ipsec;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public record EspPayload(
        IpHeader header,
        int spi,
        int seqNumber,
        ByteArray data) implements Ipv4Payload, Ipv6Payload {

    public EspPayload(IpHeader header, int spi, int seqNumber, byte[] data) {
        this(header, spi, seqNumber, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.putInt(spi);
        out.putInt(seqNumber);
        out.put(data.array());
    }

    @Override
    public int length() {
        return header.length() + 8 + data.length();
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header) {
        int spi = in.getInt();
        int seqNumber = in.getInt();
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new EspPayload(header, spi, seqNumber, data);
    }

    public byte[] rawData() {
        return data.array();
    }

    public EspData asEspData(int icvLength) {
        return EspData.fromEspPayload(this, icvLength);
    }
}
