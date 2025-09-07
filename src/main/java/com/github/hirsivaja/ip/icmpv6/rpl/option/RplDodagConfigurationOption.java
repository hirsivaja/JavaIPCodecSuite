package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public record RplDodagConfigurationOption(
        byte pcs,
        byte dioIntervalMax,
        byte dioIntervalMin,
        byte dioRedundancyConstant,
        short maxRankIncrease,
        short minHopRankIncrease,
        short ocp,
        byte defaultLifetime,
        short lifetimeUnit) implements RplOption {
    private static final int LEN = 14;

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) LEN);
        out.put(pcs);
        out.put(dioIntervalMax);
        out.put(dioIntervalMin);
        out.put(dioRedundancyConstant);
        out.putShort(maxRankIncrease);
        out.putShort(minHopRankIncrease);
        out.putShort(ocp);
        out.put((byte) 0); // RESERVED
        out.put(defaultLifetime);
        out.putShort(lifetimeUnit);
    }

    @Override
    public int length() {
        return 16;
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.DODAG_CONFIGURATION;
    }

    public static RplDodagConfigurationOption decode(ByteBuffer in){
        byte len = in.get();
        if(len != LEN){
            throw new IllegalArgumentException("Invalid length " + len);
        }
        byte pcs = in.get();
        byte dioIntervalMax = in.get();
        byte dioIntervalMin = in.get();
        byte dioRedundancyConstant = in.get();
        short maxRankIncrease = in.getShort();
        short minHopRankIncrease = in.getShort();
        short ocp = in.getShort();
        in.get(); // RESERVED
        byte defaultLifetime = in.get();
        short lifetimeUnit = in.getShort();
        return new RplDodagConfigurationOption(pcs, dioIntervalMax, dioIntervalMin, dioRedundancyConstant,
                maxRankIncrease, minHopRankIncrease, ocp, defaultLifetime, lifetimeUnit);
    }
}
