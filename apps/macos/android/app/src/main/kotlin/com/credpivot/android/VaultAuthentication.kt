package com.credpivot.android

import android.app.Activity
import android.app.AlertDialog
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import android.widget.EditText
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.util.concurrent.ExecutorService

/** App 和系统填充共用验证，避免两套主密码周期或生物识别规则。 */
internal class VaultAuthentication(
    private val activity: Activity,
    private val secure: SecureStore,
    private val worker: ExecutorService,
    private val currentEpoch: () -> Long,
) {
    private val strings = AndroidStrings(activity)
    private val main = Handler(Looper.getMainLooper())
    private var authentication: CancellationSignal? = null
    private fun status() = NativeAgent.call("status")
    private fun failure(result: MethodChannel.Result, error: Exception) {
        if (error is AgentFailure) result.error(error.code,
            if (error.code == "bad_unlock") strings.get(R.string.authentication_password_wrong) else error.message, error.details)
        else result.error("authentication_failed", strings.get(R.string.authentication_failed), null)
    }
    private fun work(result: MethodChannel.Result, action: () -> Any?) {
        val epoch = currentEpoch()
        worker.execute {
            try {
                if (epoch != currentEpoch()) throw AgentFailure("locked", "验证已取消")
                val value = action()
                main.post { if (epoch == currentEpoch()) result.success(value) else result.success(false) }
            } catch (error: Exception) { main.post { failure(result, error) } }
        }
    }
    private fun policy(): JSONObject? {
        val bytes = secure.read("unlock-policy") ?: return null
        return try { JSONObject(bytes.toString(Charsets.UTF_8)) } finally { bytes.fill(0) }
    }

    fun restorePolicy() {
        try { policy()?.let { NativeAgent.call("local_unlock_policy_set", "policy" to it) } }
        catch (_: Exception) { /* 密钥失效时保留主密码入口，不使用未保护的时间戳。 */ }
    }

    fun persistPolicy() {
        // 主密码已验证成功；生物识别偏好保存失败不能把已完成的解锁或建库报告成失败。
        try {
            val material = NativeAgent.call("local_unlock_material").getJSONObject("material")
            val bytes = material.getJSONObject("policy").toString().toByteArray()
            try { secure.write("unlock-policy", bytes) } finally { bytes.fill(0) }
        } catch (_: Exception) {
            try { secure.disableBiometric() } catch (_: Exception) {}
        }
    }

    fun authenticate(mode: String, reason: String, callback: MethodChannel.Result) {
        if (authentication != null) { callback.error("auth_busy", strings.get(R.string.authentication_busy), null); return }
        val generation = currentEpoch()
        val cancellation = CancellationSignal()
        val completed = java.util.concurrent.atomic.AtomicBoolean(false)
        val result = object : MethodChannel.Result {
            override fun success(value: Any?) {
                if (completed.compareAndSet(false, true)) callback.success(if (cancellation.isCanceled || generation != currentEpoch()) false else value)
            }
            override fun error(code: String, message: String?, details: Any?) {
                if (completed.compareAndSet(false, true)) {
                    if (cancellation.isCanceled || generation != currentEpoch()) callback.success(false)
                    else callback.error(code, message, details)
                }
            }
            override fun notImplemented() { if (completed.compareAndSet(false, true)) callback.notImplemented() }
        }
        authentication = cancellation
        // 取消立即结束调用；不等待迟到的系统回调，且绝不自动重试验证。
        cancellation.setOnCancelListener { main.post { finishAuthentication(cancellation); result.success(false) } }
        worker.execute {
            try {
                val state = status()
                if (mode == "authenticateTouchId" && state.optBoolean("sensitive_auth_active")) {
                    main.post {
                        finishAuthentication(cancellation)
                        result.success(generation == currentEpoch() && !cancellation.isCanceled)
                    }; return@execute
                }
                if (mode == "password" || state.optBoolean("master_password_required") || (mode != "enableBiometric" && !secure.biometricConfigured)) {
                    main.post {
                        if (generation != currentEpoch() || cancellation.isCanceled) { finishAuthentication(cancellation); result.success(false) }
                        else passwordPrompt(mode, result, cancellation)
                    }
                    return@execute
                }
                val cipher = secure.biometricCipher(mode == "enableBiometric")
                main.post {
                    if (generation != currentEpoch() || cancellation.isCanceled) { finishAuthentication(cancellation); result.success(false); return@post }
                    val prompt = BiometricPrompt.Builder(activity).setTitle(strings.get(R.string.authentication_title))
                        .setDescription(reason.take(160)).setNegativeButton(strings.get(android.R.string.cancel), activity.mainExecutor) { _, _ -> cancellation.cancel() }
                        .apply {
                            if (android.os.Build.VERSION.SDK_INT >= 30) {
                                setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                            }
                        }.build()
                    prompt.authenticate(BiometricPrompt.CryptoObject(cipher), cancellation, activity.mainExecutor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationError(code: Int, text: CharSequence) {
                                finishAuthentication(cancellation); result.success(false)
                            }
                            override fun onAuthenticationSucceeded(value: BiometricPrompt.AuthenticationResult) {
                                if (generation != currentEpoch() || cancellation.isCanceled) { finishAuthentication(cancellation); result.success(false); return }
                                work(result) {
                                    try {
                                        if (cancellation.isCanceled || generation != currentEpoch()) return@work false
                                        if (mode == "enableBiometric") {
                                            val bytes = NativeAgent.call("local_unlock_material").getJSONObject("material").toString().toByteArray()
                                            try { secure.enroll(cipher, bytes) } finally { bytes.fill(0) }
                                        } else {
                                            val bytes = secure.decrypt(cipher)
                                            val material = try { JSONObject(bytes.toString(Charsets.UTF_8)) } finally { bytes.fill(0) }
                                            val currentPolicy = policy() ?: throw AgentFailure("master_required", "请使用主密码验证")
                                            if (currentPolicy.getString("binding") != material.getJSONObject("policy").getString("binding")) {
                                                throw AgentFailure("master_required", "保险库已变更，请重新启用生物识别")
                                            }
                                            material.put("policy", currentPolicy)
                                            if (!status().optBoolean("unlocked")) {
                                                NativeAgent.call("unlock_local", "material" to material)
                                                persistPolicy()
                                            } else {
                                                val active = NativeAgent.call("local_unlock_material").getJSONObject("material")
                                                if (active.getJSONObject("policy").getString("binding") != currentPolicy.getString("binding")) {
                                                    throw AgentFailure("master_required", "保险库已变更，请使用主密码")
                                                }
                                                NativeAgent.call("sensitive_auth_grant")
                                            }
                                        }
                                        true
                                    } finally { main.post { finishAuthentication(cancellation) } }
                                }
                            }
                        })
                }
            } catch (error: Exception) { main.post { finishAuthentication(cancellation); failure(result, error) } }
        }
    }

    private fun passwordPrompt(mode: String, result: MethodChannel.Result, signal: CancellationSignal) {
        val input = EditText(activity).apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO
            imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            setSingleLine(); hint = strings.get(R.string.authentication_master_hint)
        }
        val dialog = AlertDialog.Builder(activity).setTitle(strings.get(R.string.authentication_master_title)).setView(input)
            .setNegativeButton(strings.get(android.R.string.cancel)) { _, _ -> finishAuthentication(signal); result.success(false) }
            .setPositiveButton(strings.get(R.string.authentication_verify), null).create()
        dialog.setCanceledOnTouchOutside(false)
        dialog.setOnCancelListener { finishAuthentication(signal); result.success(false) }
        signal.setOnCancelListener { main.post {
            finishAuthentication(signal); result.success(false)
            if (dialog.isShowing) dialog.cancel()
        } }
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (signal.isCanceled) return@setOnClickListener
                val password = input.text.toString()
                input.text.clear(); dialog.dismiss()
                work(result) {
                    try {
                        if (signal.isCanceled) return@work false
                        val unlocked = status().optBoolean("unlocked")
                        NativeAgent.call(if (unlocked) "verify_master_password" else "unlock_password", "password" to password)
                        persistPolicy()
                        if (mode == "enableBiometric") throw AgentFailure("biometric_retry", "主密码验证成功，请再次点击启用生物识别")
                        true
                    } finally { main.post { finishAuthentication(signal) } }
                }
            }
        }
        dialog.show()
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    private fun finishAuthentication(signal: CancellationSignal) {
        // 迟到的旧验证回调不能清除刚开始的新验证。
        if (authentication === signal) authentication = null
    }

    fun cancelAuthentication() { authentication?.cancel() }

}
