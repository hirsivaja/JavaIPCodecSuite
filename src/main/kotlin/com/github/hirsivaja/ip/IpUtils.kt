package com.github.hirsivaja.ip

import java.nio.ByteBuffer
import java.util.logging.Logger

object IpUtils {
    private val LOG: Logger = Logger.getLogger(IpUtils::class.java.name)

    fun calculateInternetChecksum(data: ByteArray): Short {
        val buf: ByteBuffer = ByteBuffer.wrap(data)
        var sum: Long = 0
        while (buf.hasRemaining()) {
            sum += if (buf.remaining() > 1) {
                buf.getShort().toInt() and 0xFFFF
            } else {
                (buf.get().toInt() shl 8) and 0xFFFF
            }
        }
        return ((((sum and 0xFFFF) + (sum shr 16)).inv()) and 0xFFFF).toShort()
    }

    fun verifyInternetChecksum(checksumData: ByteArray): Boolean {
        return verifyInternetChecksum(checksumData, 0.toShort())
    }

    fun verifyInternetChecksum(checksumData: ByteArray, actual: Short): Boolean {
        val expected = calculateInternetChecksum(checksumData)
        if(expected != actual) {
            LOG.warning { "CRC mismatch!" }
        }
        return expected == actual
    }

    fun ensureInternetChecksum(checksumData: ByteArray) {
        ensureInternetChecksum(checksumData, 0.toShort())
    }

    fun ensureInternetChecksum(checksumData: ByteArray, actual: Short) {
        val expected = calculateInternetChecksum(checksumData)
        require(expected == actual) { "The calculated checksum $actual was not the provided checksum $expected" }
    }
}
