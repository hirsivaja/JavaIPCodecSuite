package com.github.hirsivaja.ip.icmp;

import java.nio.ByteBuffer;

public interface IcmpMessage {
    int BASE_LEN = 4;

    IcmpType type();
    IcmpCode code();
    void encode(ByteBuffer out);
    int length();

    static IcmpMessage decode(ByteBuffer in, IcmpType type, IcmpCode code) {
        return switch (type) {
            case IcmpTypes.ECHO_REPLY -> EchoReply.decode(in);
            case IcmpTypes.DESTINATION_UNREACHABLE -> DestinationUnreachable.decode(in, code);
            case IcmpTypes.SOURCE_QUENCH -> SourceQuench.decode(in);
            case IcmpTypes.REDIRECT_MESSAGE -> Redirect.decode(in, code);
            case IcmpTypes.ECHO_REQUEST -> EchoRequest.decode(in);
            case IcmpTypes.ROUTER_ADVERTISEMENT -> RouterAdvertisement.decode(in);
            case IcmpTypes.ROUTER_SOLICITATION -> RouterSolicitation.decode(in);
            case IcmpTypes.TIME_EXCEEDED -> TimeExceeded.decode(in, code);
            case IcmpTypes.PARAMETER_PROBLEM -> ParameterProblem.decode(in, code);
            case IcmpTypes.TIMESTAMP -> Timestamp.decode(in);
            case IcmpTypes.TIMESTAMP_REPLY -> TimestampReply.decode(in);
            case IcmpTypes.INFORMATION_REQUEST -> InformationRequest.decode(in);
            case IcmpTypes.INFORMATION_REPLY -> InformationReply.decode(in);
            case IcmpTypes.ADDRESS_MASK_REQUEST -> AddressMaskRequest.decode(in);
            case IcmpTypes.ADDRESS_MASK_REPLY -> AddressMaskReply.decode(in);
            case IcmpTypes.TRACEROUTE -> Traceroute.decode(in, code);
            case IcmpTypes.EXTENDED_ECHO_REQUEST -> ExtendedEchoRequest.decode(in);
            case IcmpTypes.EXTENDED_ECHO_REPLY -> ExtendedEchoReply.decode(in, code);
            default -> GenericIcmpMessage.decode(in, type, code);
        };
    }
}
