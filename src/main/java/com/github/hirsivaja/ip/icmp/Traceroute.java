package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public record Traceroute(
        IcmpCode code,
        short idNumber,
        short outboundHopCount,
        short returnHopCount,
        int outputLinkSpeed,
        int outputLinkMtu) implements IcmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(idNumber);
        out.putShort((short) 0); // UNUSED
        out.putShort(outboundHopCount);
        out.putShort(returnHopCount);
        out.putInt(outputLinkSpeed);
        out.putInt(outputLinkMtu);
    }

    @Override
    public int length() {
        return 16;
    }

    public static IcmpMessage decode(ByteBuffer in, IcmpCode code) {
        short idNumber = in.getShort();
        in.getShort(); // UNUSED
        short outboundHopCount = in.getShort();
        short returnHopCount = in.getShort();
        int outputLinkSpeed = in.getInt();
        int outputLinkMtu = in.getInt();
        return new Traceroute(code, idNumber, outboundHopCount, returnHopCount, outputLinkSpeed, outputLinkMtu);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.TRACEROUTE;
    }
}
