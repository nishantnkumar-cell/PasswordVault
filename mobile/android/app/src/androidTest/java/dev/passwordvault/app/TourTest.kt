package dev.passwordvault.app

import android.content.Intent
import android.graphics.Bitmap
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Walks through the app the way a first-time user would and saves a
 * screenshot of each screen. Run by mobile/scripts/android-ui-test.sh on
 * phone, tablet and foldable emulators; a second run on the same device
 * starts from the unlock screen instead of creating a vault.
 *
 * Sample data uses placeholder names only (docs/user-guide/README.md).
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class TourTest {
    @get:Rule val rule = createEmptyComposeRule()

    private val args = InstrumentationRegistry.getArguments()
    private val device = args.getString("device") ?: "device"
    private val shots = File(ApplicationProvider.getApplicationContext<VaultApp>().filesDir, "screenshots").apply { mkdirs() }
    private var n = 0
    private lateinit var scenario: ActivityScenario<MainActivity>

    @Test
    fun tour() {
        val context = ApplicationProvider.getApplicationContext<VaultApp>()
        val intent = Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_ALLOW_SCREENSHOTS, true)
        scenario = ActivityScenario.launch(intent)
        try {
            rule.waitForIdle()
            if (exists("Create a new vault")) createVault() else unlock("unlock")
            addLogin()
            addCard()
            tab("Codes"); shot("codes")
            tab("Generator"); shot("generator")
            tab("Settings"); shot("settings")
            text("Lock now").performScrollTo().performClick()
            waitFor("Unlock")
            unlock("locked")
        } catch (e: Throwable) {
            runCatching { shot("failure") }
            throw e
        }
    }

    private fun createVault() {
        shot("welcome")
        text("Create a new vault").performClick()
        val fields = rule.onAllNodes(hasSetTextAction())
        fields[0].performTextInput(PHRASE)
        fields[1].performTextInput(PHRASE)
        shot("create")
        text("Create vault").performClick()
        waitFor("Your recovery code", 180_000)
        shot("recovery-code")
        text("I wrote it down").performClick()
        text("Continue").performClick()
        waitFor("New item")
        shot("items-empty")
    }

    private fun unlock(name: String) {
        shot(name)
        rule.onAllNodes(hasSetTextAction()).onFirst().performTextInput(PHRASE)
        rule.onNode(hasText("Unlock") and hasClickAction()).performClick()
        waitFor("New item", 180_000)
    }

    private fun addLogin() {
        if (exists("Example Mail")) return
        newItem("Login")
        field("Title").performTextInput("Example Mail")
        field("Username or email").performTextInput("alex@example.com")
        field("Website").performTextInput("mail.example.com")
        field("Setup key or otpauth:// link").performScrollTo().performTextInput("GEZDGNBVGY3TQOJQ")
        save("Example Mail")
        shot("login")
        back()
    }

    private fun addCard() {
        if (exists("Everyday Card")) return
        newItem("Card")
        field("Title").performTextInput("Everyday Card")
        field("Name on card").performTextInput("Alex Example")
        field("Card number").performTextInput("4111111111111111")
        field("Expires (MM/YY)").performTextInput("08/29")
        save("Everyday Card")
        shot("card")
        back()
        waitFor("Example Mail")
        shot("items")
    }

    private fun newItem(kind: String) {
        text("New item").performClick()
        text(kind).performClick()
        waitFor("Save")
    }

    private fun save(title: String) {
        text("Save").performClick()
        rule.waitUntil(30_000) { !exists("Save") && exists(title) }
    }

    /** On a phone the item opens full screen; on wide screens Back does nothing harmful. */
    private fun back() {
        scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }
        rule.waitForIdle()
    }

    private fun tab(label: String) {
        rule.onAllNodes(hasText(label) and hasClickAction()).onFirst().performClick()
        rule.waitForIdle()
    }

    private fun field(label: String): SemanticsNodeInteraction =
        rule.onAllNodes(hasSetTextAction() and hasText(label)).onFirst()

    private fun text(s: String): SemanticsNodeInteraction = rule.onAllNodesWithText(s).onFirst()

    private fun exists(s: String) = rule.onAllNodesWithText(s).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(s: String, millis: Long = 30_000) = rule.waitUntil(millis) { exists(s) }

    private fun shot(name: String) {
        rule.waitForIdle()
        n += 1
        val file = File(shots, "%s-%02d-%s.png".format(device, n, name))
        val bitmap = rule.onRoot().captureToImage().asAndroidBitmap()
        file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private companion object {
        /** A throwaway password for an emulator-only test vault. */
        const val PHRASE = "correct horse battery staple"
    }
}
