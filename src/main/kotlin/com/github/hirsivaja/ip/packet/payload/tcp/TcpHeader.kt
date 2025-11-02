package com.github.hirsivaja.ip.packet.payload.tcp

import com.github.hirsivaja.ip.DataArray
import java.nio.ByteBuffer

data class TcpHeader(
    val srcPort: UShort,
    val dstPort: UShort,
    val sequenceNumber: UInt,
    val ackNumber: UInt,
    val flags: Byte,
    val windowSize: UShort,
    val checksum: Short,
    val urgentPointer: UShort,
    val options: DataArray
) {

    constructor(
        srcPort: UShort,
        dstPort: UShort,
        sequenceNumber: UInt,
        ackNumber: UInt,
        flags: Byte,
        windowSize: UShort,
        checksum: Short,
        urgentPointer:
        UShort, options: ByteArray
    ) : this(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, DataArray(options))

    fun encode(out: ByteBuffer) {
        out.putShort(srcPort.toShort())
        out.putShort(dstPort.toShort())
        out.putInt(sequenceNumber.toInt())
        out.putInt(ackNumber.toInt())
        out.put((((options.length() / 4) + 5) shl DATA_OFFSET_SHIFT).toByte())
        out.put(flags)
        out.putShort(windowSize.toShort())
        out.putShort(checksum)
        out.putShort(urgentPointer.toShort())
        out.put(options.data)
    }

    fun length() : Int {
        return TCP_HEADER_LEN + options.length()
    }

    companion object {
        fun decode(buf: ByteBuffer): TcpHeader {
            val srcPort: UShort = buf.getShort().toUShort()
            val dstPort: UShort = buf.getShort().toUShort()
            val sequenceNumber: UInt = buf.getInt().toUInt()
            val ackNumber: UInt = buf.getInt().toUInt()
            val dataOffset: Int = (buf.get().toInt() ushr DATA_OFFSET_SHIFT) and 0x0F
            val flags: Byte = buf.get()
            val windowSize: UShort = buf.getShort().toUShort()
            val checksum: Short = buf.getShort()
            val urgentPointer: UShort = buf.getShort().toUShort()
            val options = ByteArray((dataOffset - 5) * 4)
            buf[options]
            return TcpHeader(srcPort, dstPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, options)
        }

        const val TCP_HEADER_LEN: Int = 20
        private const val DATA_OFFSET_SHIFT: Int = 4
    }
}
