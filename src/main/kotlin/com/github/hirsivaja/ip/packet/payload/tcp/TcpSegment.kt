package com.github.hirsivaja.ip.packet.payload.tcp

import com.github.hirsivaja.ip.DataArray
import com.github.hirsivaja.ip.IpUtils
import com.github.hirsivaja.ip.packet.header.IpHeader
import com.github.hirsivaja.ip.packet.payload.IpPayload
import com.github.hirsivaja.ip.packet.payload.Ipv4Payload
import com.github.hirsivaja.ip.packet.payload.Ipv6Payload
import java.nio.ByteBuffer

data class TcpSegment(val tcpHeader : TcpHeader, val data: DataArray) : Ipv4Payload, Ipv6Payload {
    constructor(tcpHeader : TcpHeader, data: ByteArray) : this(tcpHeader, DataArray(data))

    override fun encode(out: ByteBuffer) {
        tcpHeader.encode(out)
        out.put(data.data)
    }

    override fun length() : Int {
        return tcpHeader.length() + data.length()
    }

    companion object {
        fun decode(buf: ByteBuffer, ensureChecksum: Boolean, header: IpHeader): IpPayload {
            val tcpHeader: TcpHeader = TcpHeader.decode(buf)
            val data = ByteArray(buf.remaining())
            buf[data]
            val segment = TcpSegment(tcpHeader, data)
            if(ensureChecksum) {
                IpUtils.ensureInternetChecksum(generateChecksumData(header, segment))
            } else {
                IpUtils.verifyInternetChecksum(generateChecksumData(header, segment))
            }
            return segment
        }

        private fun generateChecksumData(header: IpHeader, segment: TcpSegment): ByteArray {
            val checksumBuf = ByteBuffer.allocate(header.pseudoHeaderLength() + segment.length())
            checksumBuf.put(header.generatePseudoHeader())
            segment.tcpHeader.encode(checksumBuf)
            checksumBuf.put(segment.data.data)
            val checksumData = ByteArray(checksumBuf.rewind().remaining())
            checksumBuf[checksumData]
            return checksumData
        }
    }
}
