package com.github.hirsivaja.ip.packet.payload.udp

import com.github.hirsivaja.ip.DataArray
import com.github.hirsivaja.ip.IpUtils
import com.github.hirsivaja.ip.packet.header.IpHeader
import com.github.hirsivaja.ip.packet.payload.Ipv4Payload
import com.github.hirsivaja.ip.packet.payload.Ipv6Payload
import java.nio.ByteBuffer

data class UdpDatagram(val udpHeader: UdpHeader, val data: DataArray) : Ipv4Payload, Ipv6Payload {
    constructor(udpHeader: UdpHeader, data: ByteArray) : this(udpHeader, DataArray(data))

    override fun encode(out: ByteBuffer) {
        udpHeader.encode(out)
        out.put(data.data)
    }

    override fun length() : Int {
        return UdpHeader.UDP_HEADER_LEN + data.length()
    }

    companion object {
        fun decode(buf: ByteBuffer, ensureChecksum: Boolean, header: IpHeader) : UdpDatagram {
            val udpHeader: UdpHeader = UdpHeader.decode(buf)
            val data = ByteArray(udpHeader.len.toInt() - UdpHeader.UDP_HEADER_LEN)
            buf[data]
            val datagram = UdpDatagram(udpHeader, data)
            if(ensureChecksum) {
                IpUtils.ensureInternetChecksum(generateChecksumData(header, datagram))
            } else {
                IpUtils.verifyInternetChecksum(generateChecksumData(header, datagram))
            }
            return datagram
        }

        private fun generateChecksumData(header: IpHeader, datagram: UdpDatagram): ByteArray {
            val checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength() + datagram.length())
            checksumBuf.put(header.generatePseudoHeader())
            datagram.udpHeader.encode(checksumBuf)
            checksumBuf.put(datagram.data.data)
            val checksumData = ByteArray(checksumBuf.rewind().remaining())
            checksumBuf[checksumData]
            return checksumData
        }
    }
}
