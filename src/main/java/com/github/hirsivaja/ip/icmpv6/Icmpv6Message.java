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

    Icmpv6Type getType();
    byte getCode();
    void encode(ByteBuffer out);
    int getLength();

    static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        switch (type) {
            case DESTINATION_UNREACHABLE: return DestinationUnreachable.decode(in, code);
            case PACKET_TOO_BIG: return PacketTooBig.decode(in, code);
            case TIME_EXCEEDED: return TimeExceeded.decode(in, code);
            case PARAMETER_PROBLEM: return ParameterProblem.decode(in, code);
            case ECHO_REQUEST: return EchoRequest.decode(in);
            case ECHO_RESPONSE: return EchoResponse.decode(in);
            case MULTICAST_LISTENER_QUERY: return MulticastListenerQueryMessage.decode(in, type, code);
            case MULTICAST_LISTENER_REPORT:
            case MULTICAST_LISTENER_DONE: return GenericMldMessage.decode(in, type, code);
            case ROUTER_SOLICITATION: return RouterSolicitation.decode(in);
            case ROUTER_ADVERTISEMENT: return RouterAdvertisement.decode(in);
            case NEIGHBOR_SOLICITATION: return NeighborSolicitation.decode(in);
            case NEIGHBOR_ADVERTISEMENT: return NeighborAdvertisement.decode(in);
            case REDIRECT_MESSAGE: return RedirectMessage.decode(in);
            case MULTICAST_LISTENER_REPORT_V2: return MulticastListenerReportV2Message.decode(in);
            case RPL: return RplControlMessage.decode(in, RplPayloadType.getRplPayloadType(code));
            default: throw new IllegalArgumentException("The type " + type + " is not implemented");
        }
    }
}
