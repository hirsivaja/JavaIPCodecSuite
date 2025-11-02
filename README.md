**The Java IP Codec Suite**

This is the Kotlin version of the library.

The `jipcs` contains the following codecs.

On [internet layer](https://en.wikipedia.org/wiki/Internet_layer):
* IPv4 packet [(Internet Protocol version 4)](https://en.wikipedia.org/wiki/Internet_Protocol_version_4) [(RFC 791)](https://datatracker.ietf.org/doc/html/rfc791#page-11)
* IPv6 packet [(Internet Protocol version 6)](https://en.wikipedia.org/wiki/Internet_Protocol_version_6) [(RFC 8200)](https://datatracker.ietf.org/doc/html/rfc8200#page-6)

On [transport layer](https://en.wikipedia.org/wiki/Transport_layer):
* TCP segment [(Transmission Control Protocol)](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) [(RFC 9293)](https://datatracker.ietf.org/doc/html/rfc9293#name-header-format)
* UDP datagram [(User Datagram Protocol)](https://en.wikipedia.org/wiki/User_Datagram_Protocol) [(RFC 768)](https://datatracker.ietf.org/doc/html/rfc768)

Requirements:
* Java 21 or newer
* This library does not have any external dependencies

Basic usage:
* To decode an IPv4 or IPv6 packet with headers call IpPacket.fromBytes(ipPacket: ByteArray) -method
* To encode your IPv4 or IPv6 object call IpPacket.toBytes() -method

This project is licensed under the terms of the MIT license.
