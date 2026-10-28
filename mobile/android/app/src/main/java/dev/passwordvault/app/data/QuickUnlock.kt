package dev.passwordvault.app.data

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Fingerprint and face unlock (docs/mobile.md, "Quick unlock").
 *
 * After a full unlock, the vault key is parked under a random 32-byte wrap
 * key ([uniffi.vault_mobile.VaultSession.park]). The parked key goes in app
 * storage; the wrap key is encrypted under an AES key in the Android Keystore
 * (StrongBox when the phone has one) that only a strong biometric check
 * releases, and that Android deletes when fingerprints or faces change.
 */
class QuickUnlock(private val context: Context) {
    private val file = File(context.noBackupFilesDir, "quick-unlock.bin")

    /** Stored state: the encrypted wrap key and the parked vault key. */
    class Sealed(val iv: ByteArray, val wrappedKey: ByteArray, val parked: ByteArray)

    class Unavailable(message: String) : Exception(message)

    /** Whether the phone has a strong biometric enrolled. */
    fun hardwareReady(): Boolean =
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    val isEnabled: Boolean get() = file.exists()

    fun read(): Sealed? = runCatching {
        DataInputStream(file.inputStream().buffered()).use { s ->
            check(s.readInt() == VERSION)
            fun bytes() = ByteArray(s.readInt()).also { s.readFully(it) }
            Sealed(bytes(), bytes(), bytes())
        }
    }.getOrNull()

    /** Forget the parked key and the Keystore key. */
    fun disable() {
        file.delete()
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    /**
     * Turn on quick unlock for [park], which wraps the open vault's key under
     * the given 32 bytes. Asks for a fingerprint or face once.
     */
    suspend fun enable(activity: FragmentActivity, park: (ByteArray) -> ByteArray) {
        if (!hardwareReady()) throw Unavailable("Set up a fingerprint or face unlock in Android settings first.")
        disable()
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, createKey())
        val authed = prompt(activity, cipher, "Turn on quick unlock", "Confirm it's you")
        val wrap = ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            val parked = park(wrap)
            val wrapped = authed.doFinal(wrap)
            write(Sealed(authed.iv, wrapped, parked))
        } finally {
            wrap.fill(0)
        }
    }

    /**
     * Ask for a fingerprint or face and return the wrap key and parked key.
     * The caller must zero the wrap key after use.
     */
    suspend fun unwrap(activity: FragmentActivity): Pair<ByteArray, ByteArray> {
        val sealed = read() ?: throw Unavailable("Quick unlock is off.")
        val key = keyStore().getKey(ALIAS, null) as? SecretKey
            ?: run { disable(); throw Unavailable("Quick unlock was reset. Unlock with your master password.") }
        val cipher = Cipher.getInstance(TRANSFORM)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.iv))
        } catch (e: KeyPermanentlyInvalidatedException) {
            disable()
            throw Unavailable("Your fingerprints or face changed, so quick unlock was turned off. Unlock with your master password.")
        }
        val authed = prompt(activity, cipher, "Unlock Secret Vault", "Use your fingerprint or face")
        return authed.doFinal(sealed.wrappedKey) to sealed.parked
    }

    private fun write(s: Sealed) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        DataOutputStream(tmp.outputStream().buffered()).use { o ->
            o.writeInt(VERSION)
            for (b in listOf(s.iv, s.wrappedKey, s.parked)) {
                o.writeInt(b.size)
                o.write(b)
            }
        }
        check(tmp.renameTo(file)) { "could not save quick unlock" }
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun createKey(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setKeySize(256)
            setUserAuthenticationRequired(true)
            setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                setUserAuthenticationValidityDurationSeconds(-1)
            }
            if (strongBox) setIsStrongBoxBacked(true)
        }.build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            gen.init(spec(strongBox = true))
            gen.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            gen.init(spec(strongBox = false))
            gen.generateKey()
        }
    }

    private suspend fun prompt(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        subtitle: String,
    ): Cipher = suspendCancellableCoroutine { cont ->
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher
                if (c != null) cont.resume(c) else cont.resumeWithException(Unavailable("No key was released."))
            }

            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                cont.resumeWithException(Cancelled(msg.toString()))
            }
        }
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Use master password")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        cont.invokeOnCancellation { prompt.cancelAuthentication() }
    }

    /** The user cancelled, chose the password, or the sensor gave up. */
    class Cancelled(message: String) : Exception(message)

    private companion object {
        const val ALIAS = "vault-quick-unlock-v1"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val VERSION = 1
    }
}
