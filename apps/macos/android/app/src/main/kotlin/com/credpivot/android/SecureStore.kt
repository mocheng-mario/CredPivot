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
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key("credpivot.storage.v1", false))
        cipher.updateAAD(name.toByteArray())
        save(name, cipher, cipher.doFinal(plaintext))
    }

    private fun save(name: String, cipher: Cipher, ciphertext: ByteArray) {
        val envelope = JSONObject().put("iv", encode(cipher.iv)).put("data", encode(ciphertext))
        if (!prefs.edit().putString(name, envelope.toString()).commit()) throw AgentFailure("secure_store", "安全存储写入失败")
    }

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

    val biometricConfigured: Boolean get() = prefs.contains("biometric") && store.containsAlias("credpivot.biometric.v1")

    fun biometricCipher(enroll: Boolean): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        if (enroll) {
            cipher.init(Cipher.ENCRYPT_MODE, key("credpivot.biometric.v1", true))
        } else {
            val record = JSONObject(prefs.getString("biometric", null) ?: throw AgentFailure("master_required", "请使用主密码解锁"))
            cipher.init(Cipher.DECRYPT_MODE, key("credpivot.biometric.v1", true), GCMParameterSpec(128, decode(record.getString("iv"))))
        }
        cipher.updateAAD("CredPivot Android local unlock v1".toByteArray())
        return cipher
    }

    fun enroll(cipher: Cipher, material: ByteArray) = save("biometric", cipher, cipher.doFinal(material))

    fun decrypt(cipher: Cipher): ByteArray {
        val record = JSONObject(prefs.getString("biometric", null) ?: throw AgentFailure("master_required", "请使用主密码解锁"))
        return cipher.doFinal(decode(record.getString("data")))
    }

    fun disableBiometric() {
        remove("biometric")
        if (store.containsAlias("credpivot.biometric.v1")) store.deleteEntry("credpivot.biometric.v1")
    }

    private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun decode(text: String) = Base64.decode(text, Base64.NO_WRAP)
}
