package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.icmpv6.ndp.*;
import com.github.hirsivaja.ip.icmpv6.rpl.RplControlMessage;
import com.github.hirsivaja.ip.icmpv6.rpl.payload.RplPayloadType;

import java.nio.ByteBuffer;

public interface Icmpv6Message {

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
            case ROUTER_SOLICITATION: return RouterSolicitation.decode(in);
            case ROUTER_ADVERTISEMENT: return RouterAdvertisement.decode(in);
            case NEIGHBOR_SOLICITATION: return NeighborSolicitation.decode(in);
            case NEIGHBOR_ADVERTISEMENT: return NeighborAdvertisement.decode(in);
            case REDIRECT_MESSAGE: return RedirectMessage.decode(in);
            case RPL: return RplControlMessage.decode(in, RplPayloadType.getRplPayloadType(code));
            default: throw new IllegalArgumentException("The type " + type + " is not implemented");
        }
    }
}
