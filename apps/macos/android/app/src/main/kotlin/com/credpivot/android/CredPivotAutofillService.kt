package com.credpivot.android

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.os.SystemClock
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import java.net.IDN
import java.util.UUID

internal data class FillField(val id: AutofillId, val value: String)

/** 这里只解释系统提供的表单结构，不读取保险库或在后台触发生物识别。 */
internal data class AutofillForm(
    val packageName: String,
    val domain: String?,
    val scheme: String,
    val username: FillField?,
    val password: FillField?,
    val newPassword: FillField?,
    val otp: FillField?,
    val otpFields: List<FillField> = listOfNotNull(otp),
    val otpFocused: Boolean = false,
    val port: Int? = null,
) {
    val origin: String? get() = domain?.let { "$scheme://$it" + (port?.let { value -> ":$value" } ?: "") }
    val ids: Array<AutofillId> get() = (listOfNotNull(username?.id, password?.id) + otpFields.map { it.id }).distinct().toTypedArray()
    val savedPassword: String get() = (newPassword ?: password)?.value.orEmpty()

    fun saveInfo(): SaveInfo? {
        val required = newPassword ?: password ?: return null
        return SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(required.id)).apply {
            username?.let { setOptionalIds(arrayOf(it.id)) }
        }.build()
    }

    companion object {
        fun parse(structure: AssistStructure): AutofillForm? {
            val packageName = structure.activityComponent?.packageName ?: return null
            if (packageName == "com.credpivot.android") return null
            val nodes = mutableListOf<AssistStructure.ViewNode>()
            val hosts = java.util.IdentityHashMap<AssistStructure.ViewNode, String?>()
            val schemes = java.util.IdentityHashMap<AssistStructure.ViewNode, String?>()
            val forms = java.util.IdentityHashMap<AssistStructure.ViewNode, AssistStructure.ViewNode?>()
            fun visit(node: AssistStructure.ViewNode, depth: Int, domain: String? = null, scheme: String? = null, form: AssistStructure.ViewNode? = null) {
                if (depth > 50 || nodes.size >= 5000) return
                val host = node.webDomain?.lowercase()?.trimEnd('.') ?: domain
                val protocol = node.webScheme ?: scheme
                val owner = if (node.htmlInfo?.tag.equals("form", true)) node else form
                hosts[node] = host; schemes[node] = protocol; forms[node] = owner
                nodes.add(node)
                for (i in 0 until node.childCount.coerceAtMost(5000)) visit(node.getChildAt(i), depth + 1, host, protocol, owner)
            }
            for (i in 0 until structure.windowNodeCount.coerceAtMost(20)) visit(structure.getWindowNodeAt(i).rootViewNode, 0)
            val focused = nodes.firstOrNull { it.isFocused }
            // 多个 WebView 声明不同域名时不猜测；不让隐藏 WebView 决定填充目标。
            val domains = nodes.mapNotNull { hosts[it]?.lowercase()?.trimEnd('.') }.distinct()
            val rawDomain = focused?.let { hosts[it] } ?: domains.singleOrNull()
            if (domains.size > 1 && rawDomain == null) return null
            val scheme = focused?.let { schemes[it] }?.lowercase() ?: "https"
            if (scheme !in listOf("https", "http")) return null
            var port: Int? = null
            val domain = rawDomain?.let {
                try {
                    val uri = android.net.Uri.parse("$scheme://$it")
                    if (!uri.userInfo.isNullOrEmpty() || !uri.path.isNullOrEmpty() || uri.query != null || uri.fragment != null) return null
                    if (uri.port != -1) { if (uri.port !in 1..65535) return null; port = uri.port }
                    IDN.toASCII(uri.host?.trimEnd('.') ?: return null, IDN.USE_STD3_ASCII_RULES).lowercase()
                        .takeIf { name -> name.isNotEmpty() && name.length <= 253 && !name.contains('/') && !name.contains(':') }
                } catch (_: Exception) { null }
            }
            if (rawDomain != null && domain == null) return null
            var username: FillField? = null
            var password: FillField? = null
            var newPassword: FillField? = null
            var otp: FillField? = null
            val otpCandidates = mutableListOf<FillField>()
            val singleDigits = mutableListOf<FillField>()
            val focusedForm = focused?.let { forms[it] }
            val candidates = nodes.filter { hosts[it] == rawDomain && (focusedForm == null || forms[it] === focusedForm) }
            for (node in candidates) {
                val id = node.autofillId ?: continue
                if (node.visibility != android.view.View.VISIBLE || node.autofillType != android.view.View.AUTOFILL_TYPE_TEXT) continue
                val hints = (node.autofillHints?.toList().orEmpty() + node.idEntry.orEmpty() + node.hint.orEmpty() +
                    (node.htmlInfo?.attributes?.filter { it.first in listOf("autocomplete", "name", "id", "type") }?.map { it.second }.orEmpty()))
                    .joinToString(" ").lowercase()
                val inputClass = node.inputType and InputType.TYPE_MASK_CLASS
                val variation = node.inputType and InputType.TYPE_MASK_VARIATION
                val isPassword = (inputClass == InputType.TYPE_CLASS_TEXT && variation in listOf(InputType.TYPE_TEXT_VARIATION_PASSWORD,
                    InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD, InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) ||
                    (inputClass == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD) || hints.contains("password")
                val isOtp = listOf("onetime", "one-time", "otp", "totp", "verification", "验证码", "authcode").any(hints::contains)
                val value = node.autofillValue?.takeIf { it.isText }?.textValue?.toString().orEmpty()
                if (value.length > 32768) return null
                val field = FillField(id, value)
                val html = node.htmlInfo?.attributes.orEmpty().associate { it.first.lowercase() to it.second.lowercase() }
                if (html["maxlength"] == "1" && (inputClass == InputType.TYPE_CLASS_NUMBER || html["inputmode"] in listOf("numeric", "decimal") || isOtp)) singleDigits.add(field)
                when {
                    isOtp -> { otpCandidates.add(field); if (otp == null || node.isFocused) otp = field }
                    isPassword && (hints.contains("new-password") || hints.contains("newpassword") || hints.contains("confirm")) -> if (newPassword == null) newPassword = field
                    isPassword -> if (password == null || node.isFocused) password = field
                    listOf("username", "user_name", "email", "login", "account", "用户名", "账号", "邮箱").any(hints::contains) -> if (username == null || node.isFocused) username = field
                }
            }
            val splitOtp = when {
                otp != null && singleDigits.size in 4..10 && singleDigits.any { it.id == otp?.id } -> singleDigits.toList()
                otpCandidates.size in 4..10 && otpCandidates.all { it.value.length <= 1 } -> otpCandidates.toList()
                else -> listOfNotNull(otp)
            }
            // 少数原生表单不提供用户名提示，仅在紧邻密码的文本框中回退。
            if (username == null && password != null) {
                val index = candidates.indexOfFirst { it.autofillId == password?.id }
                candidates.take(index.coerceAtLeast(0)).lastOrNull { it.autofillType == android.view.View.AUTOFILL_TYPE_TEXT && it.autofillId != null &&
                    it.visibility == android.view.View.VISIBLE && splitOtp.none { field -> field.id == it.autofillId } && it.autofillId != newPassword?.id }
                    ?.let { username = FillField(it.autofillId!!, it.autofillValue?.takeIf { v -> v.isText }?.textValue?.toString().orEmpty()) }
            }
            if (username == null && password == null && newPassword == null && otp == null) return null
            return AutofillForm(packageName, domain, scheme, username, password, newPassword, otp, splitOtp, splitOtp.any { it.id == focused?.autofillId }, port)
        }
    }
}

/** 密码及表单只短暂保存在进程内；Intent 中只传一次性随机标识。 */
internal object AutofillRequests {
    data class Pending(val form: AutofillForm, val save: Boolean, val created: Long = SystemClock.elapsedRealtime())
    private val requests = mutableMapOf<String, Pending>()
    @Synchronized fun put(form: AutofillForm, save: Boolean): String {
        requests.entries.removeAll { SystemClock.elapsedRealtime() - it.value.created > 120_000 }
        if (requests.size >= 8) requests.remove(requests.keys.first())
        return UUID.randomUUID().toString().also { requests[it] = Pending(form, save) }
    }
    @Synchronized fun take(id: String?): Pending? = requests.remove(id)?.takeIf { SystemClock.elapsedRealtime() - it.created < 120_000 }
    @Synchronized fun cancel(id: String) { requests.remove(id) }
}

class CredPivotAutofillService : AutofillService() {
    private val strings by lazy { AndroidStrings(this) }
    private fun sender(token: String): android.content.IntentSender {
        val intent = Intent(this, AutofillActivity::class.java).putExtra("request", token)
            .setData(android.net.Uri.parse("credpivot-internal://autofill/$token"))
        val flags = PendingIntent.FLAG_CANCEL_CURRENT or
            (if (android.os.Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        return PendingIntent.getActivity(this, 0, intent, flags).intentSender
    }

    @Suppress("DEPRECATION")
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        try {
            val structure = request.fillContexts.lastOrNull()?.structure
            val form = structure?.let(AutofillForm::parse)
            if (form == null || cancellationSignal.isCanceled) { callback.onSuccess(null); return }
            if (form.ids.isEmpty()) {
                callback.onSuccess(form.saveInfo()?.let { FillResponse.Builder().setSaveInfo(it).build() }); return
            }
            val token = AutofillRequests.put(form, false)
            cancellationSignal.setOnCancelListener { AutofillRequests.cancel(token) }
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, strings.get(R.string.autofill_unlock))
            }
            val response = FillResponse.Builder().setAuthentication(form.ids, sender(token), presentation)
            form.saveInfo()?.let(response::setSaveInfo)
            if (!cancellationSignal.isCanceled) callback.onSuccess(response.build())
        } catch (_: Exception) { if (!cancellationSignal.isCanceled) callback.onSuccess(null) }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        try {
            val form = request.fillContexts.lastOrNull()?.structure?.let(AutofillForm::parse)
            if (form == null || form.savedPassword.isEmpty()) { callback.onSuccess(); return }
            callback.onSuccess(sender(AutofillRequests.put(form, true)))
        } catch (_: Exception) { callback.onFailure(strings.get(R.string.autofill_save_failed)) }
    }
}
