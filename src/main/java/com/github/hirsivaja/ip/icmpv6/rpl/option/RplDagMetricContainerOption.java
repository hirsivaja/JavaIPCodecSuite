package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public class RplDagMetricContainerOption implements RplOption {

    private final byte[] dagMetricContainerData;

    public RplDagMetricContainerOption(byte[] dagMetricContainerData) {
        this.dagMetricContainerData = dagMetricContainerData;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) dagMetricContainerData.length);
        out.put(dagMetricContainerData);
    }

    @Override
    public int getLength() {
        return 2 + dagMetricContainerData.length;
    }

    @Override
    public RplOptionType getOptionType() {
        return RplOptionType.DAG_METRIC_CONTAINER;
    }

    public static RplDagMetricContainerOption decode(ByteBuffer in){
        byte len = in.get();
        byte[] dagMetricContainerData = new byte[len];
        in.get(dagMetricContainerData);
        return new RplDagMetricContainerOption(dagMetricContainerData);
    }

    public byte[] getDagMetricContainerData() {
        return dagMetricContainerData;
    }
}
