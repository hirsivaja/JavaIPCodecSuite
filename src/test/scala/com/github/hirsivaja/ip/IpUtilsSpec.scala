package com.github.hirsivaja.ip

import org.scalatest.flatspec.AnyFlatSpec

import java.util.HexFormat

class IpUtilsSpec extends AnyFlatSpec {
  it should "calculate the crc" in {
    val data = HexFormat.of.parseHex("E34F2396442799F3")
    val fullData = HexFormat.of.parseHex("E34F2396442799F31AFF")
    val expected = 0x1AFF
    val actual = IpUtils.calculateInternetChecksum(data)
    IpUtils.ensureInternetChecksum(data, actual)
    assert(expected == actual)
    assert(IpUtils.verifyInternetChecksum(data, actual))
    assert(IpUtils.verifyInternetChecksum(fullData))
    assert(IpUtils.verifyInternetChecksum(fullData))
  }

  it should "calculate the crc also" in {
    val data = HexFormat.of.parseHex("0001F203F4F5F6F7")
    val fullData = HexFormat.of.parseHex("0001F203F4F5F6F7220D")
    val expected = 0x220D
    val actual = IpUtils.calculateInternetChecksum(data)
    IpUtils.ensureInternetChecksum(data, actual)
    assert(expected == actual)
    assert(!IpUtils.verifyInternetChecksum(data, 1.toShort))
    assert(IpUtils.verifyInternetChecksum(fullData))
  }
}
