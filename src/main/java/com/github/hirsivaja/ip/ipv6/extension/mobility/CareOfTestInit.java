package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record CareOfTestInit(long careOfInitCookie, List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putLong(careOfInitCookie);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 10 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.CARE_OF_TEST_INIT;
    }

    public static CareOfTestInit decode(ByteBuffer in) {
        in.getShort(); // RESERVED
        long careOfInitCookie = in.getLong();
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new CareOfTestInit(careOfInitCookie, options);
    }
}
