**The Java IP Codec Suite**

The `jipcs` contains the following codecs:
* IPv4 header [(Internet Protocol version 4)](https://en.wikipedia.org/wiki/Internet_Protocol_version_4) [(RFC 791)](https://datatracker.ietf.org/doc/html/rfc791#page-11)
* IPv6 header [(Internet Protocol version 6)](https://en.wikipedia.org/wiki/Internet_Protocol_version_6) [(RFC 8200)](https://datatracker.ietf.org/doc/html/rfc8200#page-6)
* TCP header [(Transmission Control Protocol)](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) [(RFC 9293)](https://datatracker.ietf.org/doc/html/rfc9293#name-header-format)
* UDP header [(User Datagram Protocol)](https://en.wikipedia.org/wiki/User_Datagram_Protocol) [(RFC 768)](https://datatracker.ietf.org/doc/html/rfc768)
* ARP [(Address Resolution Protocol)](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) [(RFC 826)](https://datatracker.ietf.org/doc/html/rfc826)
* ETHERNET [(Ethernet frame)](https://en.wikipedia.org/wiki/Ethernet_frame) [(IEEE 802.3)](https://ieeexplore.ieee.org/document/9844436)
* ICMP [(Internet Control Message Protocol)](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) [(RFC 792)](https://datatracker.ietf.org/doc/html/rfc792)
* IGMP [(Internet Group Management Protocol)](https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol) [(RFC 3376)](https://datatracker.ietf.org/doc/html/rfc3376) (v1, v2 and v3)
* ICMPv6 [(Internet Control Message Protocol version 6)](https://en.wikipedia.org/wiki/ICMPv6) [(RFC 4443)](https://datatracker.ietf.org/doc/html/rfc4443) (partial implementation)
  * MLD [(Multicast Listener Discovery)](https://en.wikipedia.org/wiki/Multicast_Listener_Discovery) [(RFC 3810)](https://datatracker.ietf.org/doc/html/rfc3810) (v1 and v2)
  * NDP [(Neighbor Discovery Protocol)](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol) [(RFC 4861)](https://datatracker.ietf.org/doc/html/rfc4861)
  * RPL [(Routing Protocol for Low-Power and Lossy Networks)](https://en.wikipedia.org/wiki/IPv6_Routing_Protocol_for_Low-Power_and_Lossy_Networks) [(RFC 6550)](https://datatracker.ietf.org/doc/html/rfc6550)

Requirements:
* Java 8 or newer for 1.0.x
* Java 21 or newer for 1.1.x
* This library does not have any external dependencies

Basic usage:
* Gradle `implementation 'io.github.hirsivaja:jipcs:1.0.0'`
* To decode an IPv4 or IPv6 message with headers call IpPayload.fromBytes(byte[] ipPayload) -method
* To encode your IPv4 or IPv6 payload call IpPayload.toBytes() -method

This project is licensed under the terms of the MIT license.
