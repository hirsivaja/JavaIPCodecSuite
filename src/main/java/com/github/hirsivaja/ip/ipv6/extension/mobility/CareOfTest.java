package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record CareOfTest(
        short careOfInitNonce,
        long careOfInitCookie,
        long careOfKeygenToken,
        List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(careOfInitNonce);
        out.putLong(careOfInitCookie);
        out.putLong(careOfKeygenToken);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 18 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.CARE_OF_TEST;
    }

    public static CareOfTest decode(ByteBuffer in) {
        short careOfInitNonce = in.getShort();
        long careOfInitCookie = in.getLong();
        long careOfKeygenToken = in.getLong();
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new CareOfTest(careOfInitNonce, careOfInitCookie, careOfKeygenToken, options);
    }
}
