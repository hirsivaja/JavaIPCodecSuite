package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;

import java.nio.ByteBuffer;

public class EncapsulationPayload implements Ipv4Payload {
    private final Ipv4Header header;
    private final IpPayload encapsulatedPayload;

    public EncapsulationPayload(Ipv4Header header, IpPayload encapsulatedPayload) {
        this.header = header;
        this.encapsulatedPayload = encapsulatedPayload;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        encapsulatedPayload.encode(out);
    }

    @Override
    public int getLength() {
        return header.getLength() + encapsulatedPayload.getLength();
    }

    @Override
    public IpHeader getHeader() {
        return header;
    }

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
        IpPayload encapsulatedPayload = Ipv6Payload.decode(in);
        return new EncapsulationPayload(header, encapsulatedPayload);
    }

    @Override
    public String toString(){
        return "Encapsulated payload " + encapsulatedPayload.getLength() + "B (" + encapsulatedPayload + ")";
    }

    public IpPayload getEncapsulatedPayload() {
        return encapsulatedPayload;
    }
}
