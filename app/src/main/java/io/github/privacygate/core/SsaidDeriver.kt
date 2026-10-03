package io.github.privacygate.core

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * SSAID 派生（纯 JVM，PLAN §1.2）：
 *   v = hex16( HMAC-SHA256(key, "ssaid|" + userId + "|" + sha256(signer0) + "|" + bucket) )
 * 命中已知坏值（全 0、广为流传的 9774d56d682e549c）时把计数器追加进消息重算。
 */
object SsaidDeriver {

    /** 实测会给 app 带来异常行为的已知值，避免派生出 */
    val BAD_VALUES: Set<String> = setOf("0000000000000000", "9774d56d682e549c")

    private const val MAX_RETRIES = 64

    fun derive(key: ByteArray, userId: Int, signerHashHex: String, bucket: Long): String {
        require(key.size >= 16) { "key too short" }
        var counter = 0
        while (true) {
            val msg = if (counter == 0) "ssaid|$userId|$signerHashHex|$bucket"
            else "ssaid|$userId|$signerHashHex|$bucket|$counter"
            val v = hex16(hmacSha256(key, msg.toByteArray(Charsets.UTF_8)))
            if (v !in BAD_VALUES) return v
            if (++counter > MAX_RETRIES) return v // 每次命中概率 2^-64，纯防御性兜底
        }
    }

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /** 取摘要前 8 字节的小写十六进制（16 字符），与原生 SSAID 值格式一致 */
    fun hex16(digest: ByteArray): String {
        val sb = StringBuilder(16)
        for (i in 0 until 8) {
            sb.append(((digest[i].toInt() shr 4) and 0xF).toHexChar())
            sb.append((digest[i].toInt() and 0xF).toHexChar())
        }
        return sb.toString()
    }

    fun sha256Hex(data: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(data).toLowerHex()

    private fun Int.toHexChar(): Char = "0123456789abcdef"[this]

    private fun ByteArray.toLowerHex(): String {
        val sb = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xFF
            sb.append((v shr 4).toHexChar())
            sb.append((v and 0xF).toHexChar())
        }
        return sb.toString()
    }
}
