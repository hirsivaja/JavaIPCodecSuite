package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public interface RplOption {

    void encode(ByteBuffer out);

    int getLength();

    RplOptionType getOptionType();

    static RplOption decode(ByteBuffer in) {
        RplOptionType rplOptionType = RplOptionType.getRplOptionType(in.get());
        switch (rplOptionType) {
            case PAD_1: return RplPadOption.decode();
            case PAD_N: return RplPadNOption.decode(in);
            case DAG_METRIC_CONTAINER: return RplDagMetricContainerOption.decode(in);
            case ROUTE_INFORMATION: return RplRouteInformationOption.decode(in);
            case DODAG_CONFIGURATION: return RplDodagConfigurationOption.decode(in);
            case RPL_TARGET: return RplTargetOption.decode(in);
            case TRANSIT_INFORMATION: return RplTransitInformationOption.decode(in);
            case SOLICITED_INFORMATION: return RplSolicitedInformationOption.decode(in);
            case PREFIX_INFORMATION: return RplPrefixInformationOption.decode(in);
            case RPL_TARGET_DESCRIPTOR: return RplTargetDescriptorOption.decode(in);
            default: throw new IllegalArgumentException("Unexpected value: " + rplOptionType);
        }
    }
}
