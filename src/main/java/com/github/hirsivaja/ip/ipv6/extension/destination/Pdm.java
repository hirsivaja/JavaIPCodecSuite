package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public record Pdm(
        byte scaleDtlr,
        byte scaleDtls,
        short psnThisPacket,
        short psnLastReceived,
        short deltaTimeLastReceived,
        short deltaTimeLastSent) implements DestinationOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(scaleDtlr);
        out.put(scaleDtls);
        out.putShort(psnThisPacket);
        out.putShort(psnLastReceived);
        out.putShort(deltaTimeLastReceived);
        out.putShort(deltaTimeLastSent);
    }

    @Override
    public int length() {
        return 12;
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.PDM;
    }

    public static DestinationOption decode(ByteBuffer in) {
        byte scaleDtlr = in.get();
        byte scaleDtls = in.get();
        short psnThisPacket = in.getShort();
        short psnLastReceived = in.getShort();
        short deltaTimeLastReceived = in.getShort();
        short deltaTimeLastSent = in.getShort();
        return new Pdm(scaleDtlr, scaleDtls, psnThisPacket, psnLastReceived, deltaTimeLastReceived, deltaTimeLastSent);
    }
}
