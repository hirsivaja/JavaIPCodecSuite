package com.github.hirsivaja.ip.icmpv6.rpl.option;

import java.nio.ByteBuffer;

public interface RplOption {

    void encode(ByteBuffer out);

    int length();

    RplOptionType optionType();

    static RplOption decode(ByteBuffer in) {
        RplOptionType rplOptionType = RplOptionType.fromRplOptionType(in.get());
        return switch (rplOptionType) {
            case PAD_1 -> RplPadOption.decode();
            case PAD_N -> RplPadNOption.decode(in);
            case DAG_METRIC_CONTAINER -> RplDagMetricContainerOption.decode(in);
            case ROUTE_INFORMATION -> RplRouteInformationOption.decode(in);
            case DODAG_CONFIGURATION -> RplDodagConfigurationOption.decode(in);
            case RPL_TARGET -> RplTargetOption.decode(in);
            case TRANSIT_INFORMATION -> RplTransitInformationOption.decode(in);
            case SOLICITED_INFORMATION -> RplSolicitedInformationOption.decode(in);
            case PREFIX_INFORMATION -> RplPrefixInformationOption.decode(in);
            case RPL_TARGET_DESCRIPTOR -> RplTargetDescriptorOption.decode(in);
            default -> throw new IllegalArgumentException("Unexpected value: " + rplOptionType);
        };
    }
}
