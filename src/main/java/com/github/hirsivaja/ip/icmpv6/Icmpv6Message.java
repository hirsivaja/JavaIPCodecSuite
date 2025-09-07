package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.icmpv6.mld.GenericMldMessage;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastListenerQueryMessage;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastListenerReportV2Message;
import com.github.hirsivaja.ip.icmpv6.ndp.*;
import com.github.hirsivaja.ip.icmpv6.rpl.RplControlMessage;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayloadType;

import java.nio.ByteBuffer;

public interface Icmpv6Message {
    int BASE_LEN = 4;

    Icmpv6Type type();
    byte code();
    void encode(ByteBuffer out);
    int length();

    static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        return switch (type) {
            case DESTINATION_UNREACHABLE -> DestinationUnreachable.decode(in, code);
            case PACKET_TOO_BIG -> PacketTooBig.decode(in, code);
            case TIME_EXCEEDED -> TimeExceeded.decode(in, code);
            case PARAMETER_PROBLEM -> ParameterProblem.decode(in, code);
            case ECHO_REQUEST -> EchoRequest.decode(in);
            case ECHO_RESPONSE -> EchoResponse.decode(in);
            case MULTICAST_LISTENER_QUERY -> MulticastListenerQueryMessage.decode(in, type, code);
            case MULTICAST_LISTENER_REPORT,
                 MULTICAST_LISTENER_DONE -> GenericMldMessage.decode(in, type, code);
            case ROUTER_SOLICITATION -> RouterSolicitation.decode(in);
            case ROUTER_ADVERTISEMENT -> RouterAdvertisement.decode(in);
            case NEIGHBOR_SOLICITATION -> NeighborSolicitation.decode(in);
            case NEIGHBOR_ADVERTISEMENT -> NeighborAdvertisement.decode(in);
            case REDIRECT_MESSAGE -> RedirectMessage.decode(in);
            case MULTICAST_LISTENER_REPORT_V2 -> MulticastListenerReportV2Message.decode(in);
            case RPL -> RplControlMessage.decode(in, RplPayloadType.fromRplPayloadType(code));
            default -> GenericIcmpv6Message.decode(in, type, code);
        };
    }
}
