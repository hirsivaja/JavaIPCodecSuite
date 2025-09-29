**The Java IP Codec Suite**

The `jipcs` contains the following codecs.

On [link layer](https://en.wikipedia.org/wiki/Link_layer):
* ARP [(Address Resolution Protocol)](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) [(RFC 826)](https://datatracker.ietf.org/doc/html/rfc826)
* ETHERNET [(Ethernet frame)](https://en.wikipedia.org/wiki/Ethernet_frame) [(IEEE 802.3)](https://ieeexplore.ieee.org/document/9844436)

On [network layer](https://en.wikipedia.org/wiki/Network_layer):
* IPv4 packet [(Internet Protocol version 4)](https://en.wikipedia.org/wiki/Internet_Protocol_version_4) [(RFC 791)](https://datatracker.ietf.org/doc/html/rfc791#page-11)
  * [IP Options](https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1)
* IPv6 packet [(Internet Protocol version 6)](https://en.wikipedia.org/wiki/Internet_Protocol_version_6) [(RFC 8200)](https://datatracker.ietf.org/doc/html/rfc8200#page-6)
  * [Extension headers](https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header) and [options](https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2)
* ICMP [(Internet Control Message Protocol)](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) [(RFC 792)](https://datatracker.ietf.org/doc/html/rfc792)
  * IRDP [(ICMP Router Discovery Protocol)](https://en.wikipedia.org/wiki/ICMP_Router_Discovery_Protocol) [(RFC 1256)](https://datatracker.ietf.org/doc/html/rfc1256)
  * PROBE [(RFC 8335)](https://datatracker.ietf.org/doc/html/rfc8335)
* IGMP [(Internet Group Management Protocol)](https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol) [(RFC 3376)](https://datatracker.ietf.org/doc/html/rfc3376)
  * v1 [(RFC 1112)](https://datatracker.ietf.org/doc/html/rfc1112)
  * v2 [(RFC 2236)](https://datatracker.ietf.org/doc/html/rfc2236)
  * v3 [(RFC 3376)](https://datatracker.ietf.org/doc/html/rfc3376)
* ICMPv6 [(Internet Control Message Protocol version 6)](https://en.wikipedia.org/wiki/ICMPv6) [(RFC 4443)](https://datatracker.ietf.org/doc/html/rfc4443)
  * MLD [(Multicast Listener Discovery)](https://en.wikipedia.org/wiki/Multicast_Listener_Discovery) [(RFC 2710)](https://datatracker.ietf.org/doc/html/rfc2710)
  * NDP [(Neighbor Discovery Protocol)](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol) [(RFC 4861)](https://datatracker.ietf.org/doc/html/rfc4861)
  * RR (Router Renumbering) [(RFC 2894)](https://datatracker.ietf.org/doc/html/rfc2894)
  * IPv6 Node Information Queries [(RFC 4620)](https://datatracker.ietf.org/doc/html/rfc4620)
  * IND (Inverse Neighbor Discovery) [(RFC 3122)](https://datatracker.ietf.org/doc/html/rfc3122)
  * MLDv2 [(Multicast Listener Discovery)](https://en.wikipedia.org/wiki/Multicast_Listener_Discovery) [(RFC 3810)](https://datatracker.ietf.org/doc/html/rfc3810)
  * Mobility Support in IPv6 [(RFC 6275)](https://datatracker.ietf.org/doc/html/rfc6275)
  * SEND [(Secure Neighbor Discovery)](https://en.wikipedia.org/wiki/Secure_Neighbor_Discovery) [(RFC 3971)](https://datatracker.ietf.org/doc/html/rfc3971)
  * MRD [(Multicast Router Discovery)](https://en.wikipedia.org/wiki/Multicast_router_discovery) [(RFC 4286)](https://datatracker.ietf.org/doc/html/rfc4286)
  * RPL [(Routing Protocol for Low-Power and Lossy Networks)](https://en.wikipedia.org/wiki/IPv6_Routing_Protocol_for_Low-Power_and_Lossy_Networks) [(RFC 6550)](https://datatracker.ietf.org/doc/html/rfc6550)
  * MPL (Multicast Protocol for Low-Power and Lossy Networks) [(RFC 7731)](https://datatracker.ietf.org/doc/html/rfc7731)
  * PROBE [(RFC 8335)](https://datatracker.ietf.org/doc/html/rfc8335)

On [transport layer](https://en.wikipedia.org/wiki/Transport_layer):
* TCP segment [(Transmission Control Protocol)](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) [(RFC 9293)](https://datatracker.ietf.org/doc/html/rfc9293#name-header-format)
  * [TCP options](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1)
* UDP datagram [(User Datagram Protocol)](https://en.wikipedia.org/wiki/User_Datagram_Protocol) [(RFC 768)](https://datatracker.ietf.org/doc/html/rfc768)

Requirements:
* Java 8 or newer for 1.0.x
* Java 21 or newer for 1.1.x
* Java 25 or newer for 1.2.x
* This library does not have any external dependencies

Basic usage:
* Gradle `implementation 'io.github.hirsivaja:jipcs:1.0.0'`
* Java module-info `requires com.github.hirsivaja.jipcs;`
* To decode an IPv4 or IPv6 packet with headers call IpPacket.fromBytes(byte[] ipPacket) -method
* To encode your IPv4 or IPv6 object call IpPacket.toBytes() -method

This project is licensed under the terms of the MIT license.
