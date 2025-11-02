package com.github.hirsivaja.ip.packet

import com.github.hirsivaja.ip.packet.header.Ipv4Header
import com.github.hirsivaja.ip.packet.payload.Ipv4Payload
import java.nio.ByteBuffer

data class Ipv4Packet(override val header : Ipv4Header, override val payload : Ipv4Payload) : IpPacket {
    companion object {
        fun decode(buf: ByteBuffer, ensureChecksum: Boolean): IpPacket {
            val header = Ipv4Header.decode(buf, ensureChecksum)
            val payload = Ipv4Payload.decode(buf, ensureChecksum, header)
            return Ipv4Packet(header, payload)
        }
    }
}
