package dev.passwordvault.app.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * This phone's cloud sync access (docs/cloud-sync.md, "Phones"): the text
 * `cloudJoin` returned, with the device token in it. It is kept encrypted
 * under an AES key in the Android Keystore, in storage that is never backed
 * up. The key needs no fingerprint: syncing happens whenever the vault is
 * open.
 */
class CloudAccessStore(context: Context) {
    private val file = File(context.noBackupFilesDir, "cloud-access.bin")

    /** Whether cloud sync is on (even if the access can no longer be read). */
    val isOn: Boolean get() = file.exists()

    fun save(access: String) {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key() ?: createKey())
        val sealed = cipher.doFinal(access.toByteArray(Charsets.UTF_8))
        val tmp = File(file.parentFile, file.name + ".tmp")
        DataOutputStream(tmp.outputStream().buffered()).use { o ->
            o.writeInt(VERSION)
            for (b in listOf(cipher.iv, sealed)) {
                o.writeInt(b.size)
                o.write(b)
            }
        }
        check(tmp.renameTo(file)) { "could not save cloud sync access" }
    }

    /** The access, or null when sync is off or it cannot be decrypted. */
    fun read(): String? = runCatching {
        val (iv, sealed) = DataInputStream(file.inputStream().buffered()).use { s ->
            check(s.readInt() == VERSION)
            fun bytes(): ByteArray {
                val n = s.readInt()
                check(n in 1..MAX_PART) { "damaged" }
                return ByteArray(n).also { s.readFully(it) }
            }
            bytes() to bytes()
        }
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key()!!, GCMParameterSpec(128, iv))
        String(cipher.doFinal(sealed), Charsets.UTF_8)
    }.getOrNull()

    fun clear() {
        file.delete()
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key() = keyStore().getKey(ALIAS, null) as? SecretKey

    private fun createKey(): SecretKey {
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private companion object {
        const val ALIAS = "vault-cloud-access-v1"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val VERSION = 1
        const val MAX_PART = 64 * 1024
    }
}
