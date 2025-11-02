package com.github.hirsivaja.ip

import com.github.hirsivaja.ip.IpUtils.calculateInternetChecksum
import kotlin.test.Test
import kotlin.test.assertFalse

class IpUtilsTest {

    @Test
    fun calculateInternetChecksumTest() {
        var data: ByteArray = "E34F2396442799F3".hexToByteArray()
        var fullData: ByteArray = "E34F2396442799F31AFF".hexToByteArray()
        var expected: Short = 0x1AFF
        var actual = calculateInternetChecksum(data)
        assert(expected == actual)
        assert(IpUtils.verifyInternetChecksum(data, actual))
        assert(IpUtils.verifyInternetChecksum(fullData))

        data = "0001F203F4F5F6F7".hexToByteArray()
        fullData = "0001F203F4F5F6F7220D".hexToByteArray()
        expected = 0x220D
        actual = calculateInternetChecksum(data)
        assert(expected == actual)
        assertFalse(IpUtils.verifyInternetChecksum(data, 1.toShort()))
        assert(IpUtils.verifyInternetChecksum(fullData))
    }
}
