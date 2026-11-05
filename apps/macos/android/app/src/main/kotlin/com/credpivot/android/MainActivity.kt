package com.credpivot.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.app.AlertDialog
import android.net.Uri
import android.provider.MediaStore
import android.view.autofill.AutofillManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

class MainActivity : FlutterActivity() {
    private val uiOwner = UUID.randomUUID().toString()
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val epoch = AtomicLong()
    private lateinit var channel: MethodChannel
    private lateinit var secure: SecureStore
    private lateinit var verification: VaultAuthentication
    private var documentResult: MethodChannel.Result? = null
    private var documentSource: File? = null
    private var qrImage = false
    private var cameraImage: File? = null
    private var clipboardToken: String? = null
    private var clipboardExpiresAt = 0L
    private var bridgeDestroyed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        secure = SecureStore(this)
        verification = VaultAuthentication(this, secure, worker) { epoch.get() }
        check(NativeAgent.initialize(filesDir.absolutePath, cacheDir.absolutePath) == 0)
        worker.execute { NativeAgent.claimUiSession(uiOwner); clearTransferCache() }
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "credpivot/agent")
        channel.setMethodCallHandler(::handle)
    }

    private fun work(result: MethodChannel.Result, action: () -> Any?) {
        if (bridgeDestroyed) { result.error("closed", "当前窗口已关闭", null); return }
        val generation = epoch.get()
        worker.execute {
            try {
                if (generation != epoch.get() || bridgeDestroyed) throw AgentFailure("locked", "保险库会话已结束")
                val value = action()
                main.post {
                    if (generation != epoch.get() || bridgeDestroyed) result.error("locked", "保险库会话已结束，请重新解锁", null)
                    else result.success(value)
                }
            } catch (error: Exception) {
                main.post { failure(result, error) }
            }
        }
    }

    private fun failure(result: MethodChannel.Result, error: Exception) {
        if (error is AgentFailure) result.error(error.code, error.message, error.details)
        else result.error("operation_failed", "操作失败，请重试；生物识别不可用时请使用主密码", null)
    }

    private fun status(): JSONObject = NativeAgent.call("status").apply {
        put("local_unlock_configured", secure.biometricConfigured)
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when {
            call.method == "startAgent" -> work(result) {
                if (NativeAgent.start() != 0) throw AgentFailure("agent_not_started", "启动本机 Agent 失败")
                verification.restorePolicy(); null
            }
            call.method == "agentIsRunning" -> work(result) { NativeAgent.isRunning() == 1 }
            call.method == "restartAgent" -> work(result) {
                NativeAgent.stop(); val started = NativeAgent.start() == 0
                if (started) verification.restorePolicy()
                started
            }
            call.method == "agentRequest" -> work(result) {
                val request = JSONObject(call.arguments as String)
                val raw = NativeAgent.raw(request.toString())
                val response = JSONObject(raw)
                if (response.optString("type") == "ok") {
                    if (request.optString("type") in setOf("vault_create", "vault_change_password", "vault_open_dir")) {
                        // 旧指纹材料不能跨保险库或主密码槽位变更继续使用。
                        try { secure.disableBiometric() } catch (_: Exception) {}
                    }
                    if (request.optString("type") in setOf("vault_create", "vault_change_password")) verification.persistPolicy()
                    if (request.optString("type") == "status") {
                        response.getJSONObject("payload").put("local_unlock_configured", secure.biometricConfigured)
                    }
                }
                response.toString()
            }
            call.method == "unlockPassword" -> work(result) {
                NativeAgent.call("unlock_password", "password" to call.arguments)
                verification.persistPolicy(); true
            }
            call.method == "unlockTouchId" || call.method == "authenticateTouchId" || call.method == "enableBiometric" -> {
                verification.authenticate(call.method, call.arguments as? String ?: "验证 CredPivot 身份", result)
            }
            call.method == "disableBiometric" -> work(result) {
                NativeAgent.call("sync_control_authorize")
                secure.disableBiometric(); null
            }
            call.method == "lockVault" -> {
                epoch.incrementAndGet()
                verification.cancelAuthentication()
                work(result) { NativeAgent.call("lock"); null }
            }
            call.method == "androidPaths" -> result.success(mapOf("home" to filesDir.absolutePath,
                "cache" to cacheDir.absolutePath,
                "vault" to File(filesDir, ".credpivot/vault").absolutePath,
                "biometric" to secure.biometricConfigured))
            call.method == "syncHostInfo" -> work(result) {
                val settings = NativeAgent.call("app_settings_get").getJSONObject("settings")
                val id = status().optString("vault_id")
                val custom = settings.optJSONObject("sync_host_names")?.optString(id).orEmpty()
                mapOf("sync_host_name" to custom.ifBlank { android.os.Build.MODEL },
                    "sync_host_name_override" to custom, "computer_name" to android.os.Build.MODEL)
            }
            call.method == "setSyncHostName" -> work(result) {
                val settings = NativeAgent.call("app_settings_get").getJSONObject("settings")
                val names = settings.optJSONObject("sync_host_names") ?: JSONObject()
                names.put(status().getString("vault_id"), (call.arguments as String).trim())
                settings.put("sync_host_names", names)
                NativeAgent.call("app_settings_set", "settings" to settings); null
            }
            call.method == "pickOpenFile" -> pickDocument(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE); type = "*/*"
            }, result)
            call.method == "androidExportDocument" -> {
                val args = call.arguments as Map<*, *>
                val file = privateFile(args["path"] as String)
                documentSource = file
                pickDocument(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE); type = "application/octet-stream"
                    putExtra(Intent.EXTRA_TITLE, args["name"] as? String ?: "CredPivot.ovb")
                }, result)
            }
            call.method == "pickSaveFile" -> result.success(File(cacheDir, "export-${UUID.randomUUID()}").absolutePath)
            call.method == "readTextFile" -> work(result) {
                val file = privateFile(call.arguments as String)
                if (file.length() > 16 * 1024 * 1024) throw AgentFailure("file_size", "文件过大")
                try { file.readText() } finally {
                    if (file.parentFile == cacheDir && file.name.startsWith("import-")) file.delete()
                }
            }
            call.method == "writeTextFile" -> work(result) {
                val args = call.arguments as Map<*, *>
                privateFile(args["path"] as String).writeText(args["text"] as String); null
            }
            call.method == "copyConcealed" -> copySecret(call, result)
            call.method == "isMainWindowForeground" -> result.success(hasWindowFocus())
            call.method == "residentMemoryBytes" -> result.success(android.os.Debug.getPss().toLong() * 1024)
            call.method == "androidSecureRead" -> work(result) {
                requireUnlocked()
                val bytes = secure.read("webdav-${call.arguments as String}")
                bytes?.let { try { it.toString(Charsets.UTF_8) } finally { it.fill(0) } }
            }
            call.method == "androidSecureWrite" -> work(result) {
                // 同步操作已在入口验证；不能在网络探测后再次消耗“仅本次”的授权。
                requireUnlocked()
                val args = call.arguments as Map<*, *>
                val name = "webdav-${args["location"] as String}"
                val bytes = (args["password"] as? String)?.toByteArray()
                if (bytes == null) secure.remove(name)
                else try { secure.write(name, bytes) } finally { bytes.fill(0) }
                null
            }
            call.method == "androidDavParse" -> work(result) { AndroidDavXml.parse(call.arguments as ByteArray) }
            call.method == "androidSha256" -> work(result) {
                java.security.MessageDigest.getInstance("SHA-256").digest(call.arguments as ByteArray)
                    .joinToString("") { "%02x".format(it) }
            }
            call.method == "scanQrImage" -> scanQrImage(result)
            call.method == "androidAutofillStatus" -> result.success(getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true)
            call.method == "androidAutofillEnable" -> {
                try {
                    startActivity(Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:$packageName")))
                    result.success(null)
                } catch (_: Exception) { result.error("autofill_settings", "无法打开系统自动填充设置", null) }
            }
            call.method == "androidPasskeySupported" -> result.success(android.os.Build.VERSION.SDK_INT >= 34)
            call.method == "androidPasskeyEnable" -> {
                if (android.os.Build.VERSION.SDK_INT < 34) { result.error("unsupported", "系统通行密钥提供方需要 Android 14 或更新版本", null); return }
                try {
                    startActivity(Intent("android.settings.CREDENTIAL_PROVIDER", Uri.parse("package:$packageName")))
                    result.success(null)
                } catch (_: Exception) {
                    try { startActivity(Intent(android.provider.Settings.ACTION_SETTINGS)); result.success(null) }
                    catch (_: Exception) { result.error("settings", "请在系统设置中启用 CredPivot 通行密钥提供方", null) }
                }
            }
            else -> result.notImplemented()
        }
    }

    private fun requireUnlocked() {
        if (!status().optBoolean("unlocked")) throw AgentFailure("locked", "请先解锁保险库")
    }

    private fun privateFile(path: String): File {
        val file = File(path).canonicalFile
        if (!file.toPath().startsWith(filesDir.canonicalFile.toPath()) && !file.toPath().startsWith(cacheDir.canonicalFile.toPath())) {
            throw AgentFailure("file_path", "只允许访问应用私有文件")
        }
        return file
    }

    private fun pickDocument(intent: Intent, result: MethodChannel.Result) {
        if (documentResult != null) { result.error("busy", "文件选择尚未完成", null); return }
        documentResult = result
        try { startActivityForResult(intent, 100) }
        catch (error: Exception) {
            documentResult = null; documentSource = null; qrImage = false
            cameraImage?.delete(); cameraImage = null
            failure(result, error)
        }
    }

    private fun scanQrImage(result: MethodChannel.Result) {
        if (documentResult != null) { result.error("busy", "文件选择尚未完成", null); return }
        AlertDialog.Builder(this).setTitle("导入 MFA 二维码")
            .setItems(arrayOf("从图片选择", "拍照识别")) { _, selected ->
                qrImage = true
                if (selected == 0) pickDocument(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE); type = "image/*"
                }, result)
                else {
                    val file = File(cacheDir, "qr-camera-${UUID.randomUUID()}.jpg").apply { createNewFile() }
                    cameraImage = file
                    val uri = Uri.parse("content://$packageName.qr-image/${file.name}")
                    pickDocument(Intent(MediaStore.ACTION_IMAGE_CAPTURE).apply {
                        putExtra(MediaStore.EXTRA_OUTPUT, uri)
                        clipData = ClipData.newRawUri("CredPivot QR", uri)
                        addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }, result)
                    if (documentResult == null) { file.delete(); cameraImage = null; qrImage = false }
                }
            }.setNegativeButton(android.R.string.cancel) { _, _ -> result.success(emptyList<String>()) }
            .setOnCancelListener { result.success(emptyList<String>()) }.show()
    }

    @Deprecated("FlutterActivity uses the activity result callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 100) return
        val result = documentResult ?: return
        val source = documentSource
        val scan = qrImage
        val captured = cameraImage
        qrImage = false; cameraImage = null
        documentSource = null
        if (resultCode != RESULT_OK || (data?.data == null && captured == null)) {
            captured?.delete(); documentResult = null; result.success(if (scan) emptyList<String>() else null); return
        }
        val uri = data?.data
        worker.execute {
            try {
                val path = if (source != null) {
                    contentResolver.openOutputStream(requireNotNull(uri), "wt")?.use { output -> source.inputStream().use { it.copyTo(output) } }
                        ?: throw AgentFailure("file_write", "无法写入选定的文件")
                    source.delete(); uri.toString()
                } else if (captured != null) captured.absolutePath else {
                    val target = File(cacheDir, "import-${UUID.randomUUID()}")
                    try {
                        contentResolver.openInputStream(requireNotNull(uri))?.use { input -> target.outputStream().use { output ->
                            val buffer = ByteArray(8192); var total = 0L
                            while (true) {
                                val count = input.read(buffer); if (count < 0) break
                                total += count
                                if (total > 64L * 1024 * 1024) throw AgentFailure("file_size", "文件超过 64 MB 限制")
                                output.write(buffer, 0, count)
                            }
                            buffer.fill(0)
                        } } ?: throw AgentFailure("file_read", "无法读取选定的文件")
                        target.absolutePath
                    } catch (error: Exception) { target.delete(); throw error }
                }
                val response = if (scan) {
                    val image = File(path)
                    try { QrImageDecoder.decode(image) } finally { image.delete() }
                } else path
                main.post { documentResult = null; result.success(response) }
            } catch (error: Exception) { captured?.delete(); main.post { documentResult = null; failure(result, error) } }
        }
    }

    private fun copySecret(call: MethodCall, result: MethodChannel.Result) {
        val args = call.arguments as Map<*, *>
        val secret = args["secret"] as String
        val generation = (args["vault_lock_generation"] as Number).toLong()
        work(object : MethodChannel.Result {
            override fun error(code: String, message: String?, details: Any?) = result.error(code, message, details)
            override fun notImplemented() = result.notImplemented()
            override fun success(value: Any?) {
                val clipboard = getSystemService(ClipboardManager::class.java)
                val token = UUID.randomUUID().toString()
                val clip = ClipData.newPlainText(token, secret)
                clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
                clipboard.setPrimaryClip(clip); clipboardToken = token
                val delay = (value as Number).toLong() * 1000
                clipboardExpiresAt = android.os.SystemClock.elapsedRealtime() + delay
                main.postDelayed({
                    clearExpiredClipboard()
                }, delay)
                result.success(null)
            }
        }) {
            val state = status()
            if (!state.optBoolean("unlocked") || state.optLong("vault_lock_generation") != generation) throw AgentFailure("locked", "保险库会话已结束")
            NativeAgent.call("app_settings_get").getJSONObject("settings").getLong("clipboard_clear_seconds")
        }
    }

    override fun onResume() {
        super.onResume()
        if (!worker.isShutdown) worker.execute { NativeAgent.claimUiSession(uiOwner) }
        clearExpiredClipboard()
        if (::channel.isInitialized) channel.invokeMethod("onAppForeground", null)
    }

    private fun clearExpiredClipboard() {
        val token = clipboardToken ?: return
        if (android.os.SystemClock.elapsedRealtime() < clipboardExpiresAt) return
        // Android 限制后台读取剪贴板；后台未能清理时，回到前台再补清理，并保护其他 App 新复制的内容。
        val clipboard = getSystemService(ClipboardManager::class.java)
        if (clipboard.primaryClipDescription?.label == token) clipboard.clearPrimaryClip()
    }

    override fun onStop() {
        super.onStop()
        // 系统文件选择是用户主动发起的流程；其他离开 App 的情况立即清除当前授权。
        if (!isChangingConfigurations && documentResult == null && ::channel.isInitialized) {
            epoch.incrementAndGet(); verification.cancelAuthentication()
            channel.invokeMethod("onVaultLocked", null)
            worker.execute { try { NativeAgent.lockUiSession(uiOwner) } catch (_: Exception) {} }
            worker.execute { clearTransferCache() }
        }
    }

    private fun clearTransferCache() {
        cacheDir.listFiles()?.filter { it.isFile && (it.name.startsWith("import-") || it.name.startsWith("export-") || it.name.startsWith("backup-") || it.name.startsWith("qr-camera-")) }
            ?.forEach { it.delete() }
    }

    override fun onDestroy() {
        bridgeDestroyed = true
        verification.cancelAuthentication()
        if (::channel.isInitialized) channel.setMethodCallHandler(null)
        worker.shutdown()
        super.onDestroy()
    }
}
