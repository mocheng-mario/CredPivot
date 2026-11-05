package com.credpivot.android

import org.json.JSONArray
import org.json.JSONObject

internal class AgentFailure(val code: String, override val message: String, val details: Any? = null) : Exception(message)

internal object NativeAgent {
    private var uiOwner: String? = null
    private val requestOwner = ThreadLocal<String>()
    init { System.loadLibrary("credpivot_android") }
    external fun initialize(directory: String, temporary: String): Int
    external fun start(): Int
    external fun stop(): Int
    external fun isRunning(): Int
    private external fun request(body: ByteArray): ByteArray?

    /** 三个原生页面共用 Agent；窗口切换时，旧队列不能锁定或操作新会话。 */
    @Synchronized fun claimUiSession(owner: String) {
        requestOwner.set(uiOwner)
        try {
            if (uiOwner != owner) {
                if (uiOwner != null && isRunning() == 1) call("lock")
                uiOwner = owner
            }
            requestOwner.set(owner)
        } catch (error: Exception) {
            requestOwner.remove()
            throw error
        }
    }

    @Synchronized fun lockUiSession(owner: String) {
        if (uiOwner == owner && isRunning() == 1) {
            requestOwner.set(owner)
            call("lock")
        }
    }

    @Synchronized fun raw(body: String): String {
        val owner = requestOwner.get()
        if (uiOwner != null && owner != uiOwner) throw AgentFailure("locked", "当前验证页面已结束，请重新发起操作")
        val bytes = body.toByteArray(Charsets.UTF_8)
        val response = try { request(bytes) } finally { bytes.fill(0) }
            ?: throw AgentFailure("ffi_error", "Agent 未返回结果")
        return try { response.toString(Charsets.UTF_8) } finally { response.fill(0) }
    }

    fun call(type: String, vararg values: Pair<String, Any?>): JSONObject = call(JSONObject(mapOf("type" to type, *values)))

    fun call(body: JSONObject): JSONObject {
        val response = JSONObject(raw(body.toString()))
        if (response.optString("type") == "err") {
            throw AgentFailure(response.optString("code", "error"), response.optString("message", "操作失败"), value(response.opt("details")))
        }
        return response.optJSONObject("payload") ?: response
    }

    fun value(input: Any?): Any? = when (input) {
        null, JSONObject.NULL -> null
        is JSONObject -> input.keys().asSequence().associateWith { value(input.opt(it)) }
        is JSONArray -> (0 until input.length()).map { value(input.opt(it)) }
        else -> input
    }
}
