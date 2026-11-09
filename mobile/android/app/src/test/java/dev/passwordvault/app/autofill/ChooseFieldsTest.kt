package dev.passwordvault.app.autofill

import org.junit.Assert.assertEquals
import org.junit.Test

class ChooseFieldsTest {
    private fun user(id: String, domain: String?) = FieldCandidate(id, domain, secret = false, user = true)
    private fun pass(id: String, domain: String?) = FieldCandidate(id, domain, secret = true, user = false)

    @Test
    fun fillsOneSitesLoginForm() {
        val c = chooseFields(listOf(user("u", "example.com"), pass("p", "example.com")))
        assertEquals(ChosenFields("u", "p", "example.com"), c)
    }

    @Test
    fun passwordInAnotherSitesFrameKeepsThatSitesDomain() {
        // The page is example.com; the password field is in an iframe from
        // other.example.net. The domain looked up must be the password
        // field's own, and the page's username field is not used with it.
        val c = chooseFields(listOf(user("u", "example.com"), pass("p", "other.example.net")))
        assertEquals(ChosenFields(null, "p", "other.example.net"), c)
    }

    @Test
    fun usernameInAnotherFrameIsLeftOut() {
        val c = chooseFields(
            listOf(user("ad", "ads.example.org"), user("u", "example.com"), pass("p", "example.com")),
        )
        assertEquals(ChosenFields("u", "p", "example.com"), c)
    }

    @Test
    fun nativeFieldsHaveNoDomain() {
        // A native password field next to a web view: no domain, so only the
        // "Search Secret Vault" choice is offered.
        val c = chooseFields(listOf(user("u", "example.com"), pass("p", null)))
        assertEquals(ChosenFields(null, "p", null), c)
    }

    @Test
    fun usernameOnlyStep() {
        val c = chooseFields(listOf(user("u", "example.com")))
        assertEquals(ChosenFields("u", null, "example.com"), c)
    }

    @Test
    fun nothingToFill() {
        assertEquals(ChosenFields<String>(null, null, null), chooseFields(emptyList<FieldCandidate<String>>()))
    }
}
