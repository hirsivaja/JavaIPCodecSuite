package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record HomeTest(
        short homeInitNonce,
        long homeInitCookie,
        long homeKeygenToken,
        List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(homeInitNonce);
        out.putLong(homeInitCookie);
        out.putLong(homeKeygenToken);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 18 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.HOME_TEST;
    }

    public static HomeTest decode(ByteBuffer in) {
        short homeInitNonce = in.getShort();
        long homeInitCookie = in.getLong();
        long homeKeygenToken = in.getLong();
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new HomeTest(homeInitNonce, homeInitCookie, homeKeygenToken, options);
    }
}
