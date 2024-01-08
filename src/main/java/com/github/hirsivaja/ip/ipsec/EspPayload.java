package com.github.hirsivaja.ip.ipsec;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public class EspPayload implements Ipv4Payload, Ipv6Payload {

    private final IpHeader header;
    private final int spi;
    private final int seqNumber;
    private final byte[] data;

    public EspPayload(IpHeader header, int spi, int seqNumber, byte[] data) {
        this.header = header;
        this.spi = spi;
        this.seqNumber = seqNumber;
        this.data = data;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        out.putInt(spi);
        out.putInt(seqNumber);
        out.put(data);
    }

    @Override
    public int getLength() {
        return header.getLength() + 8 + data.length;
    }

    public static IpPayload decode(ByteBuffer in, IpHeader header) {
        int spi = in.getInt();
        int seqNumber = in.getInt();
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new EspPayload(header, spi, seqNumber, data);
    }

    @Override
    public String toString(){
        return "IPSEC Encapsulating Security Payload " + data.length + "B";
    }

    @Override
    public IpHeader getHeader() {
        return header;
    }

    public int getSpi() {
        return spi;
    }

    public int getSeqNumber() {
        return seqNumber;
    }

    public byte[] getData() {
        return data;
    }
}
