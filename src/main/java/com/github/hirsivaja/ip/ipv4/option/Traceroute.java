package com.github.hirsivaja.ip.ipv4.option;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;
import java.nio.ByteBuffer;

public record Traceroute(short idNumber, short outboundHopCount, short returnHopCount, Ipv4Address originator) implements IpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.putShort(idNumber);
        out.putShort(outboundHopCount);
        out.putShort(outboundHopCount);
        originator.encode(out);
    }

    @Override
    public int length() {
        return 12;
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.TRACEROUTE;
    }

    public static Traceroute decode(ByteBuffer in){
        short idNumber = in.getShort();
        short outboundHopCount = in.getShort();
        short returnHopCount = in.getShort();
        Ipv4Address originator = Ipv4Address.decode(in);
        return new Traceroute(idNumber, outboundHopCount, returnHopCount, originator);
    }
}
