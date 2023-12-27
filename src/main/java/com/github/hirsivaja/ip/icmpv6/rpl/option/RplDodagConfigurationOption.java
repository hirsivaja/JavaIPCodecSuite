package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplDodagConfigurationOption implements RplOption {
    private static final int LEN = 14;
    private final byte pcs;
    private final byte dioIntervalMax;
    private final byte dioIntervalMin;
    private final byte dioRedundancyConstant;
    private final short maxRankIncrease;
    private final short minHopRankIncrease;
    private final short ocp;
    private final byte defaultLifetime;
    private final short lifetimeUnit;

    @SuppressWarnings("squid:S00107")
    public RplDodagConfigurationOption(byte pcs, byte dioIntervalMax, byte dioIntervalMin, byte dioRedundancyConstant,
                                       short maxRankIncrease, short minHopRankIncrease, short ocp,
                                       byte defaultLifetime, short lifetimeUnit) {
        this.pcs = pcs;
        this.dioIntervalMax = dioIntervalMax;
        this.dioIntervalMin = dioIntervalMin;
        this.dioRedundancyConstant = dioRedundancyConstant;
        this.maxRankIncrease = maxRankIncrease;
        this.minHopRankIncrease = minHopRankIncrease;
        this.ocp = ocp;
        this.defaultLifetime = defaultLifetime;
        this.lifetimeUnit = lifetimeUnit;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
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
    public int getLength() {
        return 16;
    }

    @Override
    public RplOptionType getOptionType() {
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

    public byte getPcs() {
        return pcs;
    }

    public byte getDioIntervalMax() {
        return dioIntervalMax;
    }

    public byte getDioIntervalMin() {
        return dioIntervalMin;
    }

    public byte getDioRedundancyConstant() {
        return dioRedundancyConstant;
    }

    public short getMaxRankIncrease() {
        return maxRankIncrease;
    }

    public short getMinHopRankIncrease() {
        return minHopRankIncrease;
    }

    public short getOcp() {
        return ocp;
    }

    public byte getDefaultLifetime() {
        return defaultLifetime;
    }

    public short getLifetimeUnit() {
        return lifetimeUnit;
    }
}
