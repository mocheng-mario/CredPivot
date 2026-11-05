package com.credpivot.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.view.View
import android.view.WindowManager
import android.widget.*
import androidx.annotation.RequiresApi
import androidx.credentials.*
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

@RequiresApi(34)
class PasskeyActivity : Activity() {
    private val uiOwner = java.util.UUID.randomUUID().toString()
    private val strings by lazy { AndroidStrings(this) }
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val epoch = AtomicLong()
    private lateinit var verification: VaultAuthentication
    private lateinit var root: LinearLayout
    private lateinit var notice: TextView
    private lateinit var progress: ProgressBar
    private lateinit var rows: LinearLayout
    private lateinit var info: CallingAppInfo
    private lateinit var options: JSONObject
    private var hash: ByteArray? = null
    private var origin = ""
    private var create = false
    private var partition = "00000000-0000-4000-8000-000000000001"
    private var active = true
    private var busy = false
    private var generation = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setResult(RESULT_CANCELED)
        try {
            val creation = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            if (creation != null) {
                val request = creation.callingRequest as? CreatePublicKeyCredentialRequest ?: throw IllegalArgumentException()
                require(request.requestJson.length <= 65536)
                create = true; info = creation.callingAppInfo; options = JSONObject(request.requestJson); hash = request.clientDataHash
            } else {
                val retrieval = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: throw IllegalArgumentException()
                val request = retrieval.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().singleOrNull() ?: throw IllegalArgumentException()
                require(request.requestJson.length <= 65536)
                info = retrieval.callingAppInfo; options = JSONObject(request.requestJson); hash = request.clientDataHash
            }
        } catch (_: Exception) { finish(); return }
        verification = VaultAuthentication(this, SecureStore(this), worker) { epoch.get() }
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 32, 24, 24) }
        setContentView(ScrollView(this).apply { addView(root) })
        root.addView(TextView(this).apply { text = strings.get(if (create) R.string.passkey_create else R.string.passkey_choose); textSize = 24f })
        notice = TextView(this).apply { setPadding(0, 16, 0, 16) }; root.addView(notice)
        progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply { isIndeterminate = true; visibility = View.GONE }
        root.addView(progress)
        root.addView(Button(this).apply { text = strings.get(R.string.autofill_unlock); setOnClickListener { prepare() } })
        root.addView(Button(this).apply { text = strings.get(R.string.autofill_master_password); setOnClickListener { prepare("password") } })
        rows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }; root.addView(rows)
        root.addView(Button(this).apply { text = strings.get(android.R.string.cancel); setOnClickListener { finish() } })
        prepare()
        main.postDelayed({ if (active && !isFinishing) finish() }, 120_000)
    }

    private fun prepare(mode: String = "authenticateTouchId") {
        if (busy || !active) return
        updateBusy(true)
        notice.text = strings.get(R.string.passkey_preparing)
        execute({
            check(NativeAgent.initialize(filesDir.absolutePath, cacheDir.absolutePath) == 0)
            NativeAgent.claimUiSession(uiOwner)
            if (NativeAgent.isRunning() != 1 && NativeAgent.start() != 0) throw AgentFailure("agent_start", "Agent 启动失败")
            verification.restorePolicy()
            val rp = if (create) options.getJSONObject("rp").getString("id") else options.getString("rpId")
            origin = PasskeyCaller.origin(info, rp, hash)
        }) { updateBusy(false); authenticate(mode) { load() } }
    }

    private fun updateBusy(value: Boolean) { busy = value; if (::progress.isInitialized) progress.visibility = if (value) View.VISIBLE else View.GONE }

    private fun execute(action: () -> Unit, complete: () -> Unit = {}) {
        val current = epoch.get()
        worker.execute {
            try {
                if (!active || current != epoch.get()) return@execute
                action()
                main.post { if (active && current == epoch.get()) complete() }
            } catch (error: Exception) {
                main.post { if (active && current == epoch.get()) { updateBusy(false)
                    notice.text = if (error is AgentFailure) error.message else strings.get(R.string.passkey_failed)
                } }
            }
        }
    }

    private fun authenticate(mode: String = "authenticateTouchId", complete: () -> Unit) {
        if (busy || !active || origin.isEmpty()) return
        updateBusy(true)
        verification.authenticate(mode, strings.get(R.string.passkey_verify), object : MethodChannel.Result {
            override fun success(value: Any?) { updateBusy(false); if (active && value == true) complete() else if (active) notice.text = strings.get(R.string.autofill_cancelled) }
            override fun error(code: String, message: String?, details: Any?) { updateBusy(false); if (active) notice.text = message ?: strings.get(R.string.passkey_failed) }
            override fun notImplemented() { updateBusy(false) }
        })
    }

    private fun call(complete: Boolean = false, credential: String = ""): JSONObject = NativeAgent.call("partition_request", "partition_id" to partition,
        "request" to JSONObject().put("type", "app_passkey").put("kind", if (create) "create" else "get")
            .put("origin", origin).put("package_name", info.packageName).put("options", options)
            .put("client_data_hash", hash?.let { Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) } ?: JSONObject.NULL)
            .put("complete", complete).put("credential_id", credential))

    private fun load() {
        updateBusy(true)
        var partitions = JSONArray()
        execute({ partitions = NativeAgent.call("vault_manage", "action" to JSONObject().put("action", "partition_list")).getJSONArray("partitions") }) {
            rows.removeAllViews()
            val values = (0 until partitions.length()).map { partitions.getJSONObject(it) }
            if (values.isEmpty()) { updateBusy(false); return@execute }
            if (values.none { it.getString("id") == partition }) partition = values.first().getString("id")
            rows.addView(Spinner(this).apply {
                adapter = ArrayAdapter(this@PasskeyActivity, android.R.layout.simple_spinner_dropdown_item, values.map { it.getString("name") })
                setSelection(values.indexOfFirst { it.getString("id") == partition })
                onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                    override fun onNothingSelected(parent: AdapterView<*>?) {}
                    override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) { partition = values[position].getString("id"); showEntries() }
                }
            })
            updateBusy(false); showEntries()
        }
    }

    private fun showEntries() {
        val requestGeneration = ++generation
        var result = JSONObject()
        execute({ result = call() }) {
            if (requestGeneration != generation) return@execute
            if (rows.childCount > 1) rows.removeViews(1, rows.childCount - 1)
            notice.text = strings.get(R.string.passkey_target, result.getString("rp_id"), info.packageName, origin)
            if (create) {
                if (result.optBoolean("excluded")) { notice.append("\n" + strings.get(R.string.passkey_excluded)); return@execute }
                rows.addView(Button(this).apply {
                    text = strings.get(R.string.passkey_create_account, result.optString("username"))
                    setOnClickListener { confirm("") }
                })
            } else {
                val entries = result.optJSONArray("items") ?: JSONArray()
                if (entries.length() == 0) rows.addView(TextView(this).apply { text = strings.get(R.string.autofill_no_results) })
                for (i in 0 until entries.length()) {
                    val entry = entries.getJSONObject(i)
                    rows.addView(Button(this).apply { isAllCaps = false
                        text = "${entry.getString("username")} · ${entry.optString("display_name")}"
                        setOnClickListener { confirm(entry.getString("credential_id")) }
                    })
                }
            }
        }
    }

    private fun confirm(credential: String) {
        if (busy) return
        val selectedPartition = partition
        AlertDialog.Builder(this).setTitle(strings.get(if (create) R.string.passkey_create else R.string.passkey_choose))
            .setMessage(notice.text).setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok) { _, _ -> authenticate {
                if (selectedPartition != partition) { notice.text = strings.get(R.string.passkey_failed); return@authenticate }
                updateBusy(true)
                var response = ""
                execute({ response = call(true, credential).getJSONObject("result").toString() }) {
                    val result = Intent()
                    if (create) PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(response))
                    else PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(response)))
                    setResult(RESULT_OK, result); finish()
                }
            } }.show().window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun onStop() {
        super.onStop(); active = false; epoch.incrementAndGet(); generation++
        if (::verification.isInitialized) verification.cancelAuthentication()
        worker.execute { try { NativeAgent.lockUiSession(uiOwner) } catch (_: Exception) {} }
        if (!isFinishing) finish()
    }
    override fun onDestroy() { main.removeCallbacksAndMessages(null); hash?.fill(0); worker.shutdown(); super.onDestroy() }
}
