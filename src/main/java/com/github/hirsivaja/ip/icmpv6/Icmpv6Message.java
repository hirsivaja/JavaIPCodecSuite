package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.icmpv6.mld.GenericMldMessage;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastListenerQueryMessage;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastListenerReportV2Message;
import com.github.hirsivaja.ip.icmpv6.mpl.MplControlMessage;
import com.github.hirsivaja.ip.icmpv6.mrd.MulticastRouterAdvertisement;
import com.github.hirsivaja.ip.icmpv6.mrd.MulticastRouterSolicitation;
import com.github.hirsivaja.ip.icmpv6.mrd.MulticastRouterTermination;
import com.github.hirsivaja.ip.icmpv6.ndp.*;
import com.github.hirsivaja.ip.icmpv6.rpl.RplControlMessage;
import com.github.hirsivaja.ip.icmpv6.rr.RouterRenumberingMessage;

import java.nio.ByteBuffer;

public interface Icmpv6Message {
    Icmpv6Type type();
    Icmpv6Code code();
    void encode(ByteBuffer out);
    int length();

    @SuppressWarnings("squid:S1479")
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
            case Icmpv6Types.ROUTER_RENUMBERING -> RouterRenumberingMessage.decode(in, code);
            case Icmpv6Types.ICMP_NODE_INFORMATION_QUERY,
                 Icmpv6Types.ICMP_NODE_INFORMATION_RESPONSE -> NodeInformationMessage.decode(in, code);
            case Icmpv6Types.INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION -> InverseNeighborDiscoverySolicitation.decode(in);
            case Icmpv6Types.INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT -> InverseNeighborDiscoveryAdvertisement.decode(in);
            case Icmpv6Types.MULTICAST_LISTENER_REPORT_V2 -> MulticastListenerReportV2Message.decode(in);
            case Icmpv6Types.HOME_AGENT_ADDRESS_DISCOVERY_REQUEST -> HomeAgentAddressDiscoveryRequest.decode(in);
            case Icmpv6Types.HOME_AGENT_ADDRESS_DISCOVERY_REPLY -> HomeAgentAddressDiscoveryReply.decode(in);
            case Icmpv6Types.MOBILE_PREFIX_SOLICITATION -> MobilePrefixSolicitation.decode(in);
            case Icmpv6Types.MOBILE_PREFIX_ADVERTISEMENT -> MobilePrefixAdvertisement.decode(in);
            case Icmpv6Types.CERTIFICATION_PATH_SOLICITATION -> CertificationPathSolicitation.decode(in);
            case Icmpv6Types.CERTIFICATION_PATH_ADVERTISEMENT -> CertificationPathAdvertisement.decode(in);
            case Icmpv6Types.EXPERIMENTAL_MOBILE_PROTOCOLS -> ExperimentalMobilitySubtype.decode(in, code);
            case Icmpv6Types.MULTICAST_ROUTER_ADVERTISEMENT -> MulticastRouterAdvertisement.decode(in, code);
            case Icmpv6Types.MULTICAST_ROUTER_SOLICITATION -> MulticastRouterSolicitation.decode();
            case Icmpv6Types.MULTICAST_ROUTER_TERMINATION -> MulticastRouterTermination.decode();
            case Icmpv6Types.FMIPV6_MESSAGES -> Fmipv6Message.decode(in, code);
            case Icmpv6Types.RPL -> RplControlMessage.decode(in, code);
            case Icmpv6Types.ILNPV6_LOCATOR_UPDATE_MESSAGE -> Ilnpv6LocatorUpdateMessage.decode(in);
            case Icmpv6Types.DUPLICATE_ADDRESS_REQUEST -> DuplicateAddressRequest.decode(in);
            case Icmpv6Types.DUPLICATE_ADDRESS_CONFIRMATION -> DuplicateAddressConfirmation.decode(in);
            case Icmpv6Types.MPL_CONTROL_MESSAGE -> MplControlMessage.decode(in);
            case Icmpv6Types.EXTENDED_ECHO_REQUEST -> ExtendedEchoRequest.decode(in);
            case Icmpv6Types.EXTENDED_ECHO_REPLY -> ExtendedEchoReply.decode(in, code);
            default -> GenericIcmpv6Message.decode(in, type, code);
        };
    }
}
