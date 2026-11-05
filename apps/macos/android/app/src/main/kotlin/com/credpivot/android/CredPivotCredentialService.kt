package com.credpivot.android

import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.*
import java.util.UUID

@RequiresApi(34)
class CredPivotCredentialService : CredentialProviderService() {
    private val strings by lazy { AndroidStrings(this) }
    private fun pending(action: String, option: String = ""): PendingIntent = PendingIntent.getActivity(this, 0,
        Intent(this, if (action.startsWith("password_")) AutofillActivity::class.java else PasskeyActivity::class.java).setAction(action)
            .setData(Uri.parse("credpivot-internal://passkey/${UUID.randomUUID()}"))
            .putExtra("option", option), PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    override fun onBeginCreateCredentialRequest(request: BeginCreateCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>) {
        if (cancellationSignal.isCanceled) return
        val action = when (request) {
            is BeginCreatePublicKeyCredentialRequest -> "create"
            is BeginCreatePasswordCredentialRequest -> "password_create"
            else -> { callback.onError(CreateCredentialUnknownException("不支持该凭据类型")); return }
        }
        callback.onResult(BeginCreateCredentialResponse(listOf(CreateEntry("CredPivot", pending(action)))))
    }

    override fun onBeginGetCredentialRequest(request: BeginGetCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>) {
        if (cancellationSignal.isCanceled) return
        // 查询阶段不解锁、不读取账号，也不泄露是否存在某个站点的通行密钥。
        val entries = request.beginGetCredentialOptions.take(20).mapNotNull { option ->
            when (option) {
                is BeginGetPublicKeyCredentialOption -> PublicKeyCredentialEntry(this, strings.get(R.string.passkey_choose), pending("get", option.id), option,
                    displayName = "CredPivot", isAutoSelectAllowed = false)
                is BeginGetPasswordOption -> PasswordCredentialEntry.Builder(this, strings.get(R.string.autofill_title), pending("password_get", option.id), option)
                    .build()
                else -> null
            }
        }
        callback.onResult(BeginGetCredentialResponse(credentialEntries = entries))
    }

    override fun onClearCredentialStateRequest(request: ProviderClearCredentialStateRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>) {
        // 没有维护跨请求的登录会话；其他 App 注销不能锁定整个保险库或删除凭据。
        if (!cancellationSignal.isCanceled) callback.onResult(null)
    }
}
