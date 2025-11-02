package com.github.hirsivaja.ip.packet

import com.github.hirsivaja.ip.packet.header.Ipv6Header
import com.github.hirsivaja.ip.packet.payload.Ipv6Payload
import java.nio.ByteBuffer

data class Ipv6Packet(override val header : Ipv6Header, override val payload : Ipv6Payload) : IpPacket {
    companion object {
        fun decode(buf: ByteBuffer, ensureChecksum: Boolean): IpPacket {
            val header = Ipv6Header.decode(buf)
            val payload = Ipv6Payload.decode(buf, ensureChecksum, header)
            return Ipv6Packet(header, payload)
        }
    }
}
