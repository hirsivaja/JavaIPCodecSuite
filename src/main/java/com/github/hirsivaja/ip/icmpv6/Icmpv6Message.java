package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.icmpv6.mld.GenericMldMessage;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastListenerQueryMessage;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastListenerReportV2Message;
import com.github.hirsivaja.ip.icmpv6.ndp.*;
import com.github.hirsivaja.ip.icmpv6.rpl.RplControlMessage;

import java.nio.ByteBuffer;

public interface Icmpv6Message {
    int BASE_LEN = 4;

    Icmpv6Type type();
    Icmpv6Code code();
    void encode(ByteBuffer out);
    int length();

    static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, Icmpv6Code code) {
        return switch (type) {
            case Icmpv6Types.DESTINATION_UNREACHABLE -> DestinationUnreachable.decode(in, code);
            case Icmpv6Types.PACKET_TOO_BIG -> PacketTooBig.decode(in, code);
            case Icmpv6Types.TIME_EXCEEDED -> TimeExceeded.decode(in, code);
            case Icmpv6Types.PARAMETER_PROBLEM -> ParameterProblem.decode(in, code);
            case Icmpv6Types.ECHO_REQUEST -> EchoRequest.decode(in);
            case Icmpv6Types.ECHO_RESPONSE -> EchoResponse.decode(in);
            case Icmpv6Types.MULTICAST_LISTENER_QUERY -> MulticastListenerQueryMessage.decode(in, type, code);
            case Icmpv6Types.MULTICAST_LISTENER_REPORT,
                 Icmpv6Types.MULTICAST_LISTENER_DONE -> GenericMldMessage.decode(in, type, code);
            case Icmpv6Types.ROUTER_SOLICITATION -> RouterSolicitation.decode(in);
            case Icmpv6Types.ROUTER_ADVERTISEMENT -> RouterAdvertisement.decode(in);
            case Icmpv6Types.NEIGHBOR_SOLICITATION -> NeighborSolicitation.decode(in);
            case Icmpv6Types.NEIGHBOR_ADVERTISEMENT -> NeighborAdvertisement.decode(in);
            case Icmpv6Types.REDIRECT_MESSAGE -> RedirectMessage.decode(in);
            case Icmpv6Types.MULTICAST_LISTENER_REPORT_V2 -> MulticastListenerReportV2Message.decode(in);
            case Icmpv6Types.RPL -> RplControlMessage.decode(in, code);
            case Icmpv6Types.EXTENDED_ECHO_REQUEST -> ExtendedEchoRequest.decode(in);
            case Icmpv6Types.EXTENDED_ECHO_REPLY -> ExtendedEchoReply.decode(in, code);
            default -> GenericIcmpv6Message.decode(in, type, code);
        };
    }
}
