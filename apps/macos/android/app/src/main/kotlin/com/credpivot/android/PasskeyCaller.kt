package com.credpivot.android

import android.util.Base64
import androidx.credentials.provider.CallingAppInfo
import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

internal object PasskeyCaller {
    // 固定浏览器包名及发布签名，不能仅凭包名信任调用方声明的网页 origin。
    // 来源：https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json
    private val browsers = mapOf(
        "com.android.chrome" to "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83",
        "com.chrome.beta" to "DA:63:3D:34:B6:9E:63:AE:21:03:B4:9D:53:CE:05:2F:C5:F7:F3:C5:3A:AB:94:FD:C2:A2:08:BD:FD:14:24:9C",
        "org.mozilla.firefox" to "A7:8B:62:A5:16:5B:44:94:B2:FE:AD:9E:76:A2:80:D2:2D:93:7F:EE:62:51:AE:CE:59:94:46:B2:EA:31:9B:04",
    )
    private val allowlist = JSONObject().put("apps", JSONArray(browsers.map { (name, fingerprint) ->
        JSONObject().put("type", "android").put("info", JSONObject().put("package_name", name)
            .put("signatures", JSONArray().put(JSONObject().put("build", "release").put("cert_fingerprint_sha256", fingerprint))))
    })).toString()

    fun browserOrigin(info: CallingAppInfo): String? {
        val value = try { info.getOrigin(allowlist) } catch (_: Exception) {
            throw AgentFailure("caller_untrusted", "浏览器发布签名未通过校验，不能代替网页使用通行密钥")
        }
        if (value != null) {
            val uri = android.net.Uri.parse(value)
            if (uri.scheme != "https" || uri.host.isNullOrEmpty() || !uri.userInfo.isNullOrEmpty() ||
                !uri.path.isNullOrEmpty() || uri.query != null || uri.fragment != null) throw AgentFailure("origin_invalid", "网页来源无效")
        }
        return value
    }

    fun origin(info: CallingAppInfo, rp: String, clientHash: ByteArray?): String {
        val host = IDN.toASCII(rp, IDN.USE_STD3_ASCII_RULES).lowercase()
        if (rp != host || host.length > 253 || !host.contains('.') || host.contains('/') || host.contains(':')) throw AgentFailure("rp_invalid", "网站标识无效")
        val browserOrigin = browserOrigin(info)
        if (browserOrigin != null) {
            val uri = android.net.Uri.parse(browserOrigin)
            // 与桌面版一致，当前严格要求网页主机与 RP 相同。
            if (uri.scheme != "https" || uri.host != host || clientHash?.size != 32) throw AgentFailure("origin_invalid", "网页与通行密钥网站不一致，或缺少客户端数据校验")
            return browserOrigin
        }
        if (clientHash != null) throw AgentFailure("caller_untrusted", "原生应用不能替代浏览器指定客户端数据")
        val certificates = info.signingInfo.apkContentsSigners
        if (certificates.size != 1) throw AgentFailure("caller_signature", "无法确认应用发布签名")
        val digest = MessageDigest.getInstance("SHA-256").digest(certificates[0].toByteArray())
        val fingerprint = digest.joinToString(":") { "%02X".format(it) }
        val connection = URL("https://$host/.well-known/assetlinks.json").openConnection() as HttpsURLConnection
        connection.instanceFollowRedirects = false; connection.connectTimeout = 8000; connection.readTimeout = 8000
        try {
            if (connection.responseCode != 200) throw AgentFailure("asset_links", "该网站未授权此 Android 应用使用其通行密钥")
            val bytes = connection.inputStream.use { input ->
                val buffer = java.io.ByteArrayOutputStream()
                val block = ByteArray(4096)
                while (true) {
                    val count = input.read(block); if (count < 0) break
                    if (buffer.size() + count > 256 * 1024) throw AgentFailure("asset_links", "网站关联文件过大")
                    buffer.write(block, 0, count)
                }
                buffer.toByteArray()
            }
            val statements = JSONArray(bytes.toString(Charsets.UTF_8))
            val valid = (0 until statements.length()).any { index ->
                val statement = statements.optJSONObject(index) ?: return@any false
                val target = statement.optJSONObject("target") ?: return@any false
                val relations = statement.optJSONArray("relation") ?: JSONArray()
                val signatures = target.optJSONArray("sha256_cert_fingerprints") ?: JSONArray()
                target.optString("namespace") == "android_app" && target.optString("package_name") == info.packageName &&
                    (0 until relations.length()).any { relations.optString(it) == "delegate_permission/common.get_login_creds" } &&
                    (0 until signatures.length()).any { signatures.optString(it).equals(fingerprint, true) }
            }
            if (!valid) throw AgentFailure("asset_links", "网站未同时授权此应用的包名和发布签名")
        } finally { connection.disconnect() }
        return "android:apk-key-hash:" + Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}
