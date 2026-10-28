package dev.passwordvault.app

import android.content.Intent
import android.graphics.Bitmap
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.printToString
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso
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
    /** The throwaway vault's master password, made up by the script for each run. */
    private val phrase = args.getString("phrase") ?: error("pass -e phrase <password>")
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
            tap("Lock now")
            waitFor("Unlock")
            unlock("locked")
        } catch (e: Throwable) {
            runCatching { shot("failure") }
            throw e
        }
    }

    private fun createVault() {
        shot("welcome")
        tap("Create a new vault")
        val fields = rule.onAllNodes(hasSetTextAction())
        fields[0].performTextInput(phrase)
        fields[1].performTextInput(phrase)
        shot("create")
        tap("Create vault")
        waitFor("Your recovery code", 180_000)
        shot("recovery-code")
        tap("I wrote it down")
        rule.onNode(hasText("I wrote it down") and isToggleable()).assertIsOn()
        rule.onNode(hasText("Continue") and hasClickAction()).assertIsEnabled()
        tap("Continue")
        waitFor("New item")
        shot("items-empty")
    }

    private fun unlock(name: String) {
        shot(name)
        rule.onAllNodes(hasSetTextAction()).onFirst().performTextInput(phrase)
        // The keyboard can cover the button; scroll it into view first.
        press(rule.onNode(hasText("Unlock") and hasClickAction()))
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
        tap("New item")
        tap(kind)
        waitFor("Save")
    }

    private fun save(title: String) {
        tap("Save")
        rule.waitUntil(30_000) { !exists("Save") && exists(title) }
    }

    /**
     * On a phone the item opens full screen over the list, so go back to it.
     * Side by side the list is still showing, and Back would leave the app.
     */
    private fun back() {
        if (exists("New item")) return
        scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }
        rule.waitForIdle()
    }

    private fun tab(label: String) {
        rule.onAllNodes(hasText(label) and hasClickAction()).onFirst().performClick()
        rule.waitForIdle()
    }

    private fun field(label: String): SemanticsNodeInteraction =
        rule.onAllNodes(hasSetTextAction() and hasText(label)).onFirst()

    /**
     * The first node showing [s]. Some Material controls (the extended FAB)
     * don't merge their label into the clickable node, so fall back to the
     * label itself; a touch on it still lands on the control.
     */
    private fun text(s: String): SemanticsNodeInteraction =
        if (rule.onAllNodesWithText(s).fetchSemanticsNodes().isNotEmpty()) rule.onAllNodesWithText(s).onFirst()
        else rule.onAllNodesWithText(s, useUnmergedTree = true).onFirst()

    /** Clicks a control by its text, scrolling it into view first when it is in a scrolling page. */
    private fun tap(s: String) {
        press(text(s))
        rule.waitForIdle()
    }

    /**
     * Scrolls [node] into view and clicks it. The keyboard is closed first: a
     * touch sent while it is still moving the page can miss (seen on Create
     * vault).
     */
    private fun press(node: SemanticsNodeInteraction) {
        Espresso.closeSoftKeyboard()
        rule.waitForIdle()
        runCatching { node.performScrollTo() }
        node.performClick()
    }

    private fun exists(s: String) =
        rule.onAllNodesWithText(s).fetchSemanticsNodes().isNotEmpty() ||
            rule.onAllNodesWithText(s, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    /** Waits for [s] to show; on a timeout the failure lists what is on screen instead. */
    private fun waitFor(s: String, millis: Long = 30_000) {
        try {
            rule.waitUntil(millis) { exists(s) }
        } catch (e: ComposeTimeoutException) {
            val screen = runCatching { rule.onAllNodes(isRoot()).printToString(maxDepth = 40) }.getOrElse { "(no tree: $it)" }
            throw AssertionError("\"$s\" did not appear within $millis ms. On screen:\n$screen", e)
        }
    }

    private fun shot(name: String) {
        rule.waitForIdle()
        n += 1
        val file = File(shots, "%s-%02d-%s.png".format(device, n, name))
        val bitmap = rule.onRoot().captureToImage().asAndroidBitmap()
        file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }
}
