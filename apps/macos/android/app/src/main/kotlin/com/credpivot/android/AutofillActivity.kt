package com.credpivot.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.*
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.PasswordCredential
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest

/** 独立系统验证页，不把 Flutter 主窗口带到前台，也不通过剪贴板交付密码。 */
class AutofillActivity : Activity() {
    private val uiOwner = java.util.UUID.randomUUID().toString()
    private val strings by lazy { AndroidStrings(this) }
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val epoch = AtomicLong()
    private lateinit var verification: VaultAuthentication
    private lateinit var secure: SecureStore
    private lateinit var pending: AutofillRequests.Pending
    private lateinit var container: LinearLayout
    private lateinit var notice: TextView
    private lateinit var rows: LinearLayout
    private var selectedPartition = "00000000-0000-4000-8000-000000000001"
    private var query = ""
    private var offset = 0
    private var listGeneration = 0
    private var otpMode = false
    private var active = true
    private var busy = false
    private var searchTask: Runnable? = null
    private var providerCreate: ProviderCreateCredentialRequest? = null
    private var providerGet: ProviderGetCredentialRequest? = null
    private var submittedUsername = ""
    private var submittedPassword = ""
    private var allowedUsers = emptySet<String>()
    private val incomingUsername: String get() = if (providerCreate != null) submittedUsername else pending.form.username?.value.orEmpty()
    private val incomingPassword: String get() = if (providerCreate != null) submittedPassword else pending.form.savedPassword

    private fun receiveRequest(): AutofillRequests.Pending? {
        intent.getStringExtra("request")?.let { return AutofillRequests.take(it) }
        if (android.os.Build.VERSION.SDK_INT < 34) return null
        val creation = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val info = if (creation != null) {
            val request = creation.callingRequest as? CreatePasswordRequest ?: return null
            if (request.id.length > 32768 || request.password.length > 32768) return null
            providerCreate = creation; submittedUsername = request.id; submittedPassword = request.password
            creation.callingAppInfo
        } else {
            val retrieval = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return null
            val request = retrieval.credentialOptions.singleOrNull() as? GetPasswordOption ?: return null
            if (request.allowedUserIds.size > 1000) return null
            providerGet = retrieval; allowedUsers = request.allowedUserIds
            retrieval.callingAppInfo
        }
        val origin = PasskeyCaller.browserOrigin(info)?.let(android.net.Uri::parse)
        return AutofillRequests.Pending(AutofillForm(info.packageName, origin?.host, origin?.scheme ?: "https",
            null, null, null, null, port = origin?.port?.takeIf { it > 0 }), creation != null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setResult(RESULT_CANCELED)
        val request = try { receiveRequest() } catch (_: Exception) { null }
        if (request == null) { finish(); return }
        pending = request
        // 系统补入的结构若已切换到别的页面，不能继续使用原来的授权。
        @Suppress("DEPRECATION")
        val structure = intent.getParcelableExtra<android.app.assist.AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        if (structure != null && providerGet == null && providerCreate == null) {
            val current = AutofillForm.parse(structure)
            if (current == null || current.packageName != pending.form.packageName || current.origin != pending.form.origin || current.ids.toSet() != pending.form.ids.toSet()) { finish(); return }
        }
        secure = SecureStore(this)
        verification = VaultAuthentication(this, secure, worker) { epoch.get() }
        container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 32, 24, 24) }
        setContentView(ScrollView(this).apply { addView(container) })
        container.addView(TextView(this).apply { text = strings.get(if (pending.save) R.string.autofill_save_title else R.string.autofill_title); textSize = 24f })
        container.addView(TextView(this).apply { text = targetDescription(); setPadding(0, 16, 0, 16) })
        notice = TextView(this).apply { setPadding(0, 8, 0, 16) }; container.addView(notice)
        val retry = Button(this).apply { text = strings.get(R.string.autofill_unlock); setOnClickListener { unlock() } }
        container.addView(retry)
        container.addView(Button(this).apply { text = strings.get(R.string.autofill_master_password); setOnClickListener { authenticate("password") { showPicker() } } })
        container.addView(Button(this).apply { text = strings.get(android.R.string.cancel); setOnClickListener { finish() } })
        execute({
            check(NativeAgent.initialize(filesDir.absolutePath, cacheDir.absolutePath) == 0)
            NativeAgent.claimUiSession(uiOwner)
            if (NativeAgent.isRunning() != 1 && NativeAgent.start() != 0) throw AgentFailure("agent_start", "Agent 启动失败")
            verification.restorePolicy()
        }) { unlock() }
        main.postDelayed({ if (active && !isFinishing) finish() }, 120_000)
    }

    private fun targetDescription(): String {
        val form = pending.form
        val label = try { packageManager.getApplicationLabel(packageManager.getApplicationInfo(form.packageName, 0)).toString() } catch (_: Exception) { form.packageName }
        return strings.get(R.string.autofill_target, label, form.packageName, form.origin ?: strings.get(R.string.autofill_native_target))
    }

    private fun execute(action: () -> Unit, complete: () -> Unit = {}) {
        if (!active) return
        val generation = epoch.get()
        worker.execute {
            try {
                if (!active || generation != epoch.get()) return@execute
                action()
                main.post { if (active && generation == epoch.get()) complete() }
            } catch (error: Exception) {
                main.post { if (active && generation == epoch.get()) {
                    busy = false
                    notice.text = if (error is AgentFailure && error.code in listOf("otp_fields", "account_changed")) error.message
                        else strings.get(R.string.autofill_operation_failed)
                } }
            }
        }
    }

    private fun authenticate(mode: String = "authenticateTouchId", complete: () -> Unit) {
        if (busy || !active) return
        busy = true
        verification.authenticate(mode, strings.get(R.string.autofill_verify_reason), object : MethodChannel.Result {
            override fun success(value: Any?) {
                busy = false
                if (active && value == true) complete()
                else if (active) notice.text = strings.get(R.string.autofill_cancelled)
            }
            override fun error(code: String, message: String?, details: Any?) {
                busy = false
                if (active) notice.text = message ?: strings.get(R.string.autofill_operation_failed)
            }
            override fun notImplemented() { busy = false }
        })
    }

    private fun unlock() = authenticate { showPicker() }

    private fun scoped(type: String, vararg args: Pair<String, Any?>): JSONObject = NativeAgent.call("partition_request",
        "partition_id" to selectedPartition, "request" to JSONObject(mapOf("type" to type, *args)))

    private fun selectionKey(): String {
        val form = pending.form
        val vault = NativeAgent.call("status").getString("vault_id")
        val input = "$vault\n${form.packageName}\n${form.origin.orEmpty()}".toByteArray()
        return "autofill-" + java.security.MessageDigest.getInstance("SHA-256").digest(input).joinToString("") { "%02x".format(it) }
    }

    private fun selection(): JSONObject {
        return try {
            val bytes = secure.read(selectionKey()) ?: return JSONObject()
            try { JSONObject(bytes.toString(Charsets.UTF_8)) } finally { bytes.fill(0) }
        } catch (_: Exception) { JSONObject() }
    }

    private fun rememberLogin(id: String) {
        try {
            val bytes = JSONObject().put("partition", selectedPartition).put("login", id).toString().toByteArray()
            try { secure.write(selectionKey(), bytes) } finally { bytes.fill(0) }
        } catch (_: Exception) { /* 记忆账号失败不影响本次已授权的填充。 */ }
    }

    private fun showPicker() {
        busy = true
        var partitions = JSONArray()
        execute({
            partitions = NativeAgent.call("vault_manage", "action" to JSONObject().put("action", "partition_list")).getJSONArray("partitions")
            val previous = selection().optString("partition")
            if (previous.isNotEmpty() && !::rows.isInitialized) selectedPartition = previous
        }) {
            container.removeViews(3, container.childCount - 3)
            val choices = (0 until partitions.length()).map { partitions.getJSONObject(it) }
            if (choices.isEmpty()) { busy = false; return@execute }
            if (choices.none { it.optString("id") == selectedPartition }) selectedPartition = choices.first().getString("id")
            container.addView(Spinner(this).apply {
                adapter = ArrayAdapter(this@AutofillActivity, android.R.layout.simple_spinner_dropdown_item, choices.map { it.getString("name") })
                setSelection(choices.indexOfFirst { it.getString("id") == selectedPartition })
                onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                    override fun onNothingSelected(parent: AdapterView<*>?) {}
                    override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                        selectedPartition = choices[position].getString("id"); offset = 0; loadRows()
                    }
                }
            })
            otpMode = pending.form.otpFocused || (pending.form.otp != null && pending.form.password == null && pending.form.username == null)
            if (!pending.save && pending.form.otp != null && (pending.form.password != null || pending.form.username != null)) {
                container.addView(Switch(this).apply { text = strings.get(R.string.autofill_otp); isChecked = otpMode
                    setOnCheckedChangeListener { _, checked -> otpMode = checked; offset = 0; loadRows() } })
            }
            container.addView(EditText(this).apply {
                hint = strings.get(R.string.autofill_search); setSingleLine()
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                addTextChangedListener(object : TextWatcher {
                    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                        query = s?.toString().orEmpty().take(256); offset = 0
                        searchTask?.let(main::removeCallbacks)
                        searchTask = Runnable { loadRows() }.also { main.postDelayed(it, 250) }
                    }
                    override fun afterTextChanged(s: Editable?) {}
                })
            })
            rows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }; container.addView(rows)
            container.addView(Button(this).apply { text = strings.get(android.R.string.cancel); setOnClickListener { finish() } })
            busy = false; loadRows()
        }
    }

    private fun loadRows() {
        if (!::rows.isInitialized || !active) return
        val generation = ++listGeneration
        val partition = selectedPartition; val search = query; val pageOffset = offset; val totp = otpMode
        var items = emptyList<JSONObject>()
        var fetchedCount = 0
        var groups = emptyList<JSONObject>()
        execute({
            val result = NativeAgent.call("partition_request", "partition_id" to partition,
                "request" to JSONObject().put("type", if (totp) "totp_list" else "credential_list")
                    .put("query", search).put("limit", 100).put("offset", pageOffset))
            val array = result.optJSONArray("items") ?: JSONArray()
            // 后续账号过滤或插入网站推荐会改变展示数量，分页必须以原始页为准。
            fetchedCount = array.length()
            items = (0 until array.length()).map { array.getJSONObject(it) }
            if (totp) items = items.filter { "${it.optString("issuer")} ${it.optString("account")}".contains(search, true) }
            val domain = pending.form.domain
            if (domain != null && search.isBlank()) {
                val remembered = selection().takeIf { it.optString("partition") == partition }?.optString("login").orEmpty()
                val suggestion = try {
                    NativeAgent.call(if (totp) "browser_mfa_suggest" else "credential_suggest", "origin" to pending.form.origin,
                        "credential_id" to (if (totp) remembered else ""), "include_other_matches" to remembered.isEmpty())
                } catch (error: AgentFailure) {
                    if (!totp || remembered.isEmpty() || error.code == "locked") throw error
                    // 账号删除、迁移或网站规则修改后，旧记忆不能阻断独立 MFA。
                    NativeAgent.call("browser_mfa_suggest", "origin" to pending.form.origin, "include_other_matches" to true)
                }
                val suggested = suggestion.optJSONArray("candidates") ?: JSONArray()
                if (pageOffset == 0) {
                    val matching = (0 until suggested.length()).map { suggested.getJSONObject(it) }.filter { it.optString("partition_id") == partition }
                    val ids = matching.map { it.getString("id") }.toSet()
                    items = matching + items.filter { it.getString("id") !in ids }
                }
            }
            if (providerGet != null && allowedUsers.isNotEmpty()) items = items.filter { it.optString("username") in allowedUsers }
            if (pending.save) {
                val arrayGroups = NativeAgent.call("partition_request", "partition_id" to partition,
                    "request" to JSONObject().put("type", "credential_group_list").put("scope", "login")).optJSONArray("items") ?: JSONArray()
                groups = (0 until arrayGroups.length()).map { arrayGroups.getJSONObject(it) }
            }
        }) {
            if (generation != listGeneration) return@execute
            rows.removeAllViews(); notice.text = strings.get(R.string.autofill_manual_notice)
            if (pending.save) rows.addView(Button(this).apply {
                text = strings.get(R.string.autofill_save_new)
                setOnClickListener { saveNew(groups) }
            })
            for (item in items) {
                rows.addView(Button(this).apply {
                    text = if (totp) "${item.optString("issuer")} · ${item.optString("account")}" else
                        "${item.optString("title", item.optString("display_name", item.optString("origin")))}\n${item.optString("username")} · ${item.optString("origin")}"
                    isAllCaps = false
                    setOnClickListener { confirmSelection(item, totp) }
                })
            }
            if (items.isEmpty()) rows.addView(TextView(this).apply { text = strings.get(R.string.autofill_no_results) })
            if (!totp) {
                if (pageOffset > 0) rows.addView(Button(this).apply { text = strings.get(R.string.autofill_previous); setOnClickListener { offset = (offset - 100).coerceAtLeast(0); loadRows() } })
                if (fetchedCount >= 100) rows.addView(Button(this).apply { text = strings.get(R.string.autofill_next); setOnClickListener { offset += 100; loadRows() } })
            }
        }
    }

    private fun confirmSelection(item: JSONObject, totp: Boolean) {
        if (busy) return
        val partitionAtSelection = selectedPartition
        val title = if (totp) "${item.optString("issuer")} · ${item.optString("account")}" else
            "${item.optString("title", item.optString("display_name", item.optString("origin")))} · ${item.optString("username")}"
        val submitted = incomingUsername.ifBlank { item.optString("username") }
        val confirmation = strings.get(R.string.autofill_confirm, title, targetDescription()) +
            if (pending.save) "\n" + strings.get(R.string.autofill_submitted_account, submitted) else ""
        AlertDialog.Builder(this).setTitle(strings.get(if (pending.save) R.string.autofill_update_title else R.string.autofill_confirm_title))
            .setMessage(confirmation)
            .setNegativeButton(android.R.string.cancel, null).setPositiveButton(android.R.string.ok) { _, _ ->
                authenticate {
                    if (partitionAtSelection != selectedPartition) { notice.text = strings.get(R.string.autofill_operation_failed); return@authenticate }
                    busy = true
                    if (pending.save) execute({
                        NativeAgent.call("app_credential_password_update", "credential_id" to item.getString("id"),
                            "expected_revision" to item.getString("current_revision"),
                            "username" to submitted,
                            "password" to incomingPassword)
                    }) { saved() }
                    else fill(item, totp)
                }
            }.show().window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    @Suppress("DEPRECATION")
    private fun fill(item: JSONObject, totp: Boolean) {
        var response: FillResponse? = null
        var credentialResult: Intent? = null
        execute({
            val form = pending.form
            if (providerGet != null) {
                val secret = NativeAgent.call("credential_get", "credential_id" to item.getString("id"))
                val username = secret.getString("username")
                if (allowedUsers.isNotEmpty() && username !in allowedUsers) throw AgentFailure("account_changed", strings.get(R.string.autofill_operation_failed))
                credentialResult = Intent().also { result -> PendingIntentHandler.setGetCredentialResponse(result,
                    GetCredentialResponse(PasswordCredential(username, secret.getString("password")))) }
                rememberLogin(item.getString("id"))
                return@execute
            }
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, if (totp) item.optString("issuer") else item.optString("username"))
            }
            val dataset = Dataset.Builder(presentation)
            if (totp) {
                val code = NativeAgent.call("vault_manage", "action" to JSONObject().put("action", "totp_status")
                    .put("id", item.getString("id")).put("min_valid_seconds", 0).put("passive", false)).getString("code")
                if (form.otpFields.size > 1) {
                    if (form.otpFields.size != code.length) throw AgentFailure("otp_fields", strings.get(R.string.autofill_otp_length))
                    form.otpFields.forEachIndexed { index, field -> dataset.setValue(field.id, AutofillValue.forText(code[index].toString())) }
                } else dataset.setValue(form.otp!!.id, AutofillValue.forText(code))
            } else {
                val secret = NativeAgent.call("credential_get", "credential_id" to item.getString("id"))
                form.username?.let { dataset.setValue(it.id, AutofillValue.forText(secret.getString("username"))) }
                form.password?.let { dataset.setValue(it.id, AutofillValue.forText(secret.getString("password"))) }
                rememberLogin(item.getString("id"))
            }
            response = FillResponse.Builder().addDataset(dataset.build()).apply { form.saveInfo()?.let(::setSaveInfo) }.build()
        }) {
            setResult(RESULT_OK, credentialResult ?: Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
            finish()
        }
    }

    private fun saveNew(groups: List<JSONObject>) {
        if (busy) return
        val partitionAtSelection = selectedPartition
        val form = pending.form
        val name = EditText(this).apply { hint = strings.get(R.string.autofill_name); setText(form.domain ?: form.packageName); importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO }
        val user = EditText(this).apply { hint = strings.get(R.string.autofill_account); setText(incomingUsername); importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO }
        val group = Spinner(this).apply { adapter = ArrayAdapter(this@AutofillActivity, android.R.layout.simple_spinner_dropdown_item,
            listOf(strings.get(R.string.autofill_ungrouped)) + groups.map { it.getString("name") }) }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 8, 24, 8); addView(name); addView(user); addView(group) }
        AlertDialog.Builder(this).setTitle(strings.get(R.string.autofill_save_new)).setView(content)
            .setMessage(strings.get(R.string.autofill_save_confirm, targetDescription()))
            .setNegativeButton(android.R.string.cancel, null).setPositiveButton(android.R.string.ok) { _, _ ->
                val title = name.text.toString().take(256); val username = user.text.toString()
                val groupId = groups.getOrNull(group.selectedItemPosition - 1)?.getString("id")
                authenticate {
                    if (partitionAtSelection != selectedPartition) { notice.text = strings.get(R.string.autofill_operation_failed); return@authenticate }
                    busy = true
                    execute({ scoped("credential_save", "request_id" to java.util.UUID.randomUUID().toString(),
                        "origin" to (form.origin ?: ""), "display_name" to title,
                        "username" to username, "password" to incomingPassword, "group_id" to groupId) }) { saved() }
                }
            }.show().window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    private fun saved() {
        busy = false
        if (providerCreate != null) setResult(RESULT_OK, Intent().also { PendingIntentHandler.setCreateCredentialResponse(it, CreatePasswordResponse()) })
        notice.text = strings.get(R.string.autofill_saved)
        AlertDialog.Builder(this).setMessage(strings.get(R.string.autofill_saved)).setPositiveButton(android.R.string.ok) { _, _ -> finish() }
            .setOnCancelListener { finish() }.show()
    }

    override fun onStop() {
        super.onStop()
        active = false; epoch.incrementAndGet(); listGeneration++
        searchTask?.let(main::removeCallbacks)
        if (::verification.isInitialized) verification.cancelAuthentication()
        // 交付结果后立即结束系统填充会话，不把解锁状态留给下一个应用。
        worker.execute { try { NativeAgent.lockUiSession(uiOwner) } catch (_: Exception) {} }
        if (!isFinishing) finish()
    }

    override fun onDestroy() { main.removeCallbacksAndMessages(null); worker.shutdown(); super.onDestroy() }
}
