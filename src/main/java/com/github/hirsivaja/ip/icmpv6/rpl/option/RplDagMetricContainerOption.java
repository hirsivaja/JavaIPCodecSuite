package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record RplDagMetricContainerOption(ByteArray dagMetricContainerData) implements RplOption {

    public RplDagMetricContainerOption(byte[] dagMetricContainerData) {
        this(new ByteArray(dagMetricContainerData));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) dagMetricContainerData.length());
        out.put(dagMetricContainerData.array());
    }

    @Override
    public int length() {
        return 2 + dagMetricContainerData.length();
    }

    @Override
    public RplOptionType optionType() {
        return RplOptionType.DAG_METRIC_CONTAINER;
    }

    public static RplDagMetricContainerOption decode(ByteBuffer in){
        byte len = in.get();
        byte[] dagMetricContainerData = new byte[len];
        in.get(dagMetricContainerData);
        return new RplDagMetricContainerOption(dagMetricContainerData);
    }

    public byte[] rawDagMetricContainerData() {
        return dagMetricContainerData.array();
    }
}
