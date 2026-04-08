// package xyz
import android.util.Log
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

object PacketParser {
    private const val TAG = "PacketParser"
    private const val IP_HEADER_MIN_LEN = 20
    private const val UDP_HEADER_LEN = 8
    private const val DNS_PORT = 53
    private const val TLS_HANDSHAKE = 0x16
    private const val TLS_CLIENT_HELLO = 0x01

    // Parse DNS packet and extract queried domain
    fun parseDnsPacket(data: ByteArray, length: Int): String? {
        try {
            if (length < IP_HEADER_MIN_LEN + UDP_HEADER_LEN + 12) return null // Minimum DNS packet size

            val buffer = ByteBuffer.wrap(data, 0, length)
            val version = buffer.get(0).toInt() and 0xF0 shr 4 // IP version
            val ipHeaderLen = if (version == 4) {
                (buffer.get(0).toInt() and 0x0F) * 4
            } else if (version == 6) {
                40 // IPv6 fixed header
            } else {
                return null
            }

            if (buffer.get(9).toInt() and 0xFF != 17) return null // Not UDP
            val srcPort = buffer.getShort(ipHeaderLen).toInt() and 0xFFFF
            val dstPort = buffer.getShort(ipHeaderLen + 2).toInt() and 0xFFFF
            if (srcPort != DNS_PORT && dstPort != DNS_PORT) return null

            val dnsOffset = ipHeaderLen + UDP_HEADER_LEN
            var pos = dnsOffset + 12 // Skip DNS header
            val domainBuilder = StringBuilder()

            while (pos < length) {
                val len = data[pos++].toInt() and 0xFF
                if (len == 0) break
                if (len >= 0xC0) { // Handle DNS compression
                    pos++ // Skip pointer byte
                    break
                }
                if (pos + len > length) {
                    Log.w(TAG, "Invalid DNS length at pos $pos")
                    return null
                }
                domainBuilder.append(String(data, pos, len, StandardCharsets.UTF_8)).append('.')
                pos += len
            }

            val domain = domainBuilder.trimEnd('.').toString()
            return if (domain.isNotEmpty()) domain else null
        } catch (e: Exception) {
            Log.e(TAG, "DNS parsing error: ${e.message}")
            return null
        }
    }

    // Parse TLS Client Hello and extract SNI
    fun parseTlsSni(data: ByteArray, length: Int): String? {
        try {
            if (length < IP_HEADER_MIN_LEN + 20 + 5) return null // Minimum TCP + TLS size

            val buffer = ByteBuffer.wrap(data, 0, length)
            val version = buffer.get(0).toInt() and 0xF0 shr 4
            val ipHeaderLen = if (version == 4) {
                (buffer.get(0).toInt() and 0x0F) * 4
            } else if (version == 6) {
                40
            } else {
                return null
            }

            if (buffer.get(9).toInt() and 0xFF != 6) return null // Not TCP
            if (buffer.get(ipHeaderLen + 13).toInt() != TLS_HANDSHAKE) return null // Not TLS
            if (buffer.get(ipHeaderLen + 18).toInt() != TLS_CLIENT_HELLO) return null // Not ClientHello

            var pos = ipHeaderLen + 20 + 43 // Skip TCP header + TLS record header
            if (pos >= length) return null

            val sessionIdLen = data[pos++].toInt() and 0xFF
            pos += sessionIdLen
            if (pos + 2 > length) return null

            val cipherLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherLen
            if (pos >= length) return null

            val compressionLen = data[pos++].toInt() and 0xFF
            pos += compressionLen
            if (pos + 2 > length) return null

            val extensionsLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2
            if (pos + extensionsLen > length) return null

            var extPos = pos
            val extEnd = pos + extensionsLen
            while (extPos + 4 < extEnd && extPos < length) {
                val extType = ((data[extPos].toInt() and 0xFF) shl 8) or (data[extPos + 1].toInt() and 0xFF)
                val extLen = ((data[extPos + 2].toInt() and 0xFF) shl 8) or (data[extPos + 3].toInt() and 0xFF)
                extPos += 4
                if (extType == 0x00 && extPos + 5 <= length) { // SNI extension
                    val sniLen = ((data[extPos + 2].toInt() and 0xFF) shl 8) or (data[extPos + 3].toInt() and 0xFF)
                    val nameType = data[extPos + 4].toInt() and 0xFF
                    if (nameType == 0 && extPos + 7 <= length) { // Hostname type
                        val nameLen = ((data[extPos + 5].toInt() and 0xFF) shl 8) or (data[extPos + 6].toInt() and 0xFF)
                        if (extPos + 7 + nameLen <= length) {
                            return String(data, extPos + 7, nameLen, StandardCharsets.UTF_8)
                        }
                    }
                }
                extPos += extLen
            }
            return null
        } catch (e: Exception) {
            Log.e(TAG, "TLS SNI parsing error: ${e.message}")
            return null
        }
    }

    // Utility to check if packet is fragmented (simplified)
     fun isFragmented(data: ByteArray, length: Int): Boolean {
        val version = data[0].toInt() and 0xF0 shr 4
        if (version == 4) {
            val flagsAndOffset = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
            return (flagsAndOffset and 0x2000) != 0 || (flagsAndOffset and 0x1FFF) != 0
        }
        return false // IPv6 fragmentation not handled in this example
    }
}
