**Java IP Codecs**

Java IP codec suite. Contains the following codecs:
* IPv4 header [(RFC 791)](https://datatracker.ietf.org/doc/html/rfc791#page-11)
* IPv6 header [(RFC 8200)](https://datatracker.ietf.org/doc/html/rfc8200#page-6)
* TCP header [(RFC 9293)](https://datatracker.ietf.org/doc/html/rfc9293#name-header-format)
* UDP header [(RFC 768)](https://datatracker.ietf.org/doc/html/rfc768)
* ICMP (partial) [(RFC 792)](https://datatracker.ietf.org/doc/html/rfc792)
* ICMPv6 (partial) [(RFC 4443)](https://datatracker.ietf.org/doc/html/rfc4443)
  * NDP [(RFC 4861)](https://datatracker.ietf.org/doc/html/rfc4861)
  * RPL [(RFC 6550)](https://datatracker.ietf.org/doc/html/rfc6550)

Creating a JAR:
* Run 'gradlew jar'
* This library does not have any external dependencies. Java 8 or newer is enough to use it

Basic usage:
* To decode an IPv4 or IPv6 message with headers call IpPayload.fromBytes(byte[] ipPayload) -method
* To encode your IPv4 or IPv6 payload call IpPayload.toBytes() -method

This project is licensed under the terms of the MIT license.
