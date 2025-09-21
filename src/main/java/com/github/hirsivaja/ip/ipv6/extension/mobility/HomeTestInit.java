package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record HomeTestInit(long homeInitCookie, List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putLong(homeInitCookie);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 10 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.HOME_TEST_INIT;
    }

    public static HomeTestInit decode(ByteBuffer in) {
        in.getShort(); // RESERVED
        long homeInitCookie = in.getLong();
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new HomeTestInit(homeInitCookie, options);
    }
}
