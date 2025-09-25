package com.github.hirsivaja.ip.ipv4.option;

import java.nio.ByteBuffer;

public interface IpOption {
    static byte CONTROL = 0;
    static byte RESERVED_1 = 1;
    static byte DEBUG = 2;
    static byte RESERVED_2 = 3;

    void encode(ByteBuffer out);

    int length();

    IpOptionType optionType();

    static IpOption decode(ByteBuffer in) {
        IpOptionType optionType = IpOptionType.fromType(in.get());
        if(optionType == IpOptionType.END_OF_OPTIONS_LIST) {
            return Eool.decode();
        }
        if(optionType == IpOptionType.NO_OPERATION) {
            return Nop.decode();
        }
        int optionLength = Byte.toUnsignedInt(in.get()) - 2;
        byte[] optionBytes = new byte[optionLength];
        in.get(optionBytes);
        ByteBuffer optionBuffer = ByteBuffer.wrap(optionBytes);
        return switch (optionType) {
            case SECURITY -> Security.decode(optionBuffer);
            case LOOSE_SOURCE_ROUTE -> LooseSourceRoute.decode(optionBuffer);
            case TIME_STAMP -> Timestamp.decode(optionBuffer);
            case EXTENDED_SECURITY -> ExtendedSecurity.decode(optionBuffer);
            case COMMERCIAL_SECURITY -> CommercialSecurity.decode(optionBuffer);
            case RECORD_ROUTE -> RecordRoute.decode(optionBuffer);
            case STREAM_ID -> StreamId.decode(optionBuffer);
            case STRICT_SOURCE_ROUTE -> StrictSourceRoute.decode(optionBuffer);
            case EXPERIMENTAL_MEASUREMENT -> GenericIpOption.decode(optionBuffer, optionType);
            case MTU_PROBE -> MtuProbe.decode(optionBuffer);
            case MTU_REPLY -> MtuReply.decode(optionBuffer);
            case EXPERIMENTAL_FLOW_CONTROL -> GenericIpOption.decode(optionBuffer, optionType);
            case EXPERIMENTAL_ACCESS_CONTROL -> GenericIpOption.decode(optionBuffer, optionType);
            case ENCODE -> GenericIpOption.decode(optionBuffer, optionType);
            case IMI_TRAFFIC_DESCRIPTOR -> GenericIpOption.decode(optionBuffer, optionType);
            case EXTENDED_INTERNET_PROTOCOL -> GenericIpOption.decode(optionBuffer, optionType);
            case TRACEROUTE -> Traceroute.decode(optionBuffer);
            case ADDRESS_EXTENSION -> GenericIpOption.decode(optionBuffer, optionType);
            case ROUTER_ALERT -> RouterAlert.decode(optionBuffer);
            case SELECTIVE_DIRECTED_BROADCAST -> GenericIpOption.decode(optionBuffer, optionType);
            case DYNAMIC_PACKET_STATE -> GenericIpOption.decode(optionBuffer, optionType);
            case UPSTREAM_MULTICAST_PACKET -> GenericIpOption.decode(optionBuffer, optionType);
            case QUICK_START -> QuickStart.decode(optionBuffer);
            default -> GenericIpOption.decode(optionBuffer, optionType);
        };
    }
}
