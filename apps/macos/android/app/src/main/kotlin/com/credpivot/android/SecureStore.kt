package com.credpivot.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** 密钥由 Android Keystore 持有；生物识别密钥每次使用都需要系统授权。 */
internal class SecureStore(context: Context) {
    private val strings = AndroidStrings(context)
    private val prefs = context.getSharedPreferences("credpivot-secure", Context.MODE_PRIVATE)
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(alias: String, biometric: Boolean): SecretKey {
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val parameters = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(biometric)
        if (biometric) {
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                parameters.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            parameters.setInvalidatedByBiometricEnrollment(true)
        }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(parameters.build()); generateKey()
        }
    }

    fun write(name: String, plaintext: ByteArray) {
        val encrypted = encrypt(name, plaintext)
        if (!prefs.edit().putString(name, encrypted).commit()) throw AgentFailure("secure_store", "安全存储写入失败")
    }

    private fun encrypt(name: String, plaintext: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key("credpivot.storage.v1", false))
        cipher.updateAAD(name.toByteArray())
        return envelope(cipher.iv, cipher.doFinal(plaintext))
    }

    private fun envelope(iv: ByteArray, ciphertext: ByteArray): String =
        JSONObject().put("iv", encode(iv)).put("data", encode(ciphertext)).toString()

    fun read(name: String): ByteArray? {
        val envelope = prefs.getString(name, null)?.let(::JSONObject) ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key("credpivot.storage.v1", false), GCMParameterSpec(128, decode(envelope.getString("iv"))))
        cipher.updateAAD(name.toByteArray())
        return cipher.doFinal(decode(envelope.getString("data")))
    }

    fun remove(name: String) {
        if (!prefs.edit().remove(name).commit()) throw AgentFailure("secure_store", "安全存储清理失败")
    }

    val hasBiometricRecord: Boolean get() = prefs.contains("biometric")
    val biometricConfigured: Boolean get() = hasBiometricRecord && store.containsAlias("credpivot.biometric.v1")

    fun biometricCipher(enroll: Boolean): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        if (enroll) {
            cipher.init(Cipher.ENCRYPT_MODE, key("credpivot.biometric.v1", true))
        } else {
            val record = JSONObject(prefs.getString("biometric", null) ?: throw AgentFailure("master_required", "请使用主密码解锁"))
            cipher.init(Cipher.DECRYPT_MODE, key("credpivot.biometric.v1", true), GCMParameterSpec(128, decode(record.getString("iv"))))
        }
        return cipher
    }

    fun enroll(cipher: Cipher, material: ByteArray, policy: ByteArray) {
        // 先完成本次指纹授权的操作，再使用其他 Keystore 密钥；不在中间重建或替换 Cipher。
        val encryptedMaterial = try {
            // AAD 会触发 Keystore 操作，必须放在指纹授权后；提前调用的错误可能缓存到 doFinal 才抛出。
            cipher.updateAAD("CredPivot Android local unlock v1".toByteArray())
            envelope(cipher.iv, cipher.doFinal(material))
        }
            catch (_: Exception) { throw AgentFailure("biometric_encrypt_failed", strings.get(R.string.biometric_encrypt_failed)) }
        val encryptedPolicy = try { encrypt("unlock-policy", policy) }
            catch (_: Exception) { throw AgentFailure("biometric_policy_failed", strings.get(R.string.biometric_policy_failed)) }
        val previousMaterial = prefs.getString("biometric", null)
        val previousPolicy = prefs.getString("unlock-policy", null)
        try {
            // 两份材料同一次提交，不能把只保存了一半的设置报告为启用成功。
            if (!prefs.edit().putString("biometric", encryptedMaterial).putString("unlock-policy", encryptedPolicy).commit()) {
                throw AgentFailure("biometric_save_failed", strings.get(R.string.biometric_save_failed))
            }
        } catch (_: Exception) {
            // commit 失败时内存中的偏好也可能已更新，恢复旧值避免当前进程误报已启用。
            runCatching { prefs.edit().putString("biometric", previousMaterial).putString("unlock-policy", previousPolicy).commit() }
            throw AgentFailure("biometric_save_failed", strings.get(R.string.biometric_save_failed))
        }
    }

    fun decrypt(cipher: Cipher): ByteArray {
        val record = JSONObject(prefs.getString("biometric", null) ?: throw AgentFailure("master_required", "请使用主密码解锁"))
        // 解密也在认证成功后提交 AAD，保持与录入时完全相同的认证数据。
        cipher.updateAAD("CredPivot Android local unlock v1".toByteArray())
        return cipher.doFinal(decode(record.getString("data")))
    }

    fun clearAll() {
        if (!prefs.edit().clear().commit()) throw AgentFailure("secure_store", "安全存储清理失败")
        for (alias in listOf("credpivot.storage.v1", "credpivot.biometric.v1")) {
            runCatching { if (store.containsAlias(alias)) store.deleteEntry(alias) }
        }
    }

    fun disableBiometric() {
        remove("biometric")
        if (store.containsAlias("credpivot.biometric.v1")) store.deleteEntry("credpivot.biometric.v1")
    }

    private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun decode(text: String) = Base64.decode(text, Base64.NO_WRAP)
}
