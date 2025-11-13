package com.github.hirsivaja.ip

import java.nio.ByteBuffer
import java.util.logging.{Level, Logger}

object IpUtils {
  private val logger = Logger.getLogger("IpUtils")

  def calculateInternetChecksum(data: Array[Byte]): Short = {
    val buf = ByteBuffer.wrap(data)
    var sum = 0
    while (buf.hasRemaining) {
      if (buf.remaining > 1) {
        sum += buf.getShort & 0xFFFF
      } else {
        sum += buf.get << 8 & 0xFFFF
      }
    }
    ((~((sum & 0xFFFF) + (sum >> 16))) & 0xFFFF).toShort
  }

  def verifyInternetChecksum(checksumData: Array[Byte]): Boolean = verifyInternetChecksum(checksumData, 0.toShort)

  def verifyInternetChecksum(checksumData: Array[Byte], actual: Short): Boolean = {
    val expected = calculateInternetChecksum(checksumData)
    if (expected != actual) {
      logger.warning("CRC mismatch!")
    }
    expected == actual
  }

  def ensureInternetChecksum(checksumData: Array[Byte]): Unit = {
    ensureInternetChecksum(checksumData, 0.toShort)
  }

  def ensureInternetChecksum(checksumData: Array[Byte], actual: Short): Unit = {
    val expected = calculateInternetChecksum(checksumData)
    if (expected != actual) {
      logger.log(Level.FINEST, s"Checksum mismatch! Expected checksum $expected. Actual checksum $actual")
      throw new IllegalArgumentException("Checksum does not match!")
    }
  }
}
