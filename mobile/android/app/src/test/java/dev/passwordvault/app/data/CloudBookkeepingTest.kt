package dev.passwordvault.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudBookkeepingTest {
    private class Memory : CloudBookkeeping.Store {
        override var cloudVersion: Long? = null
        override var cloudDirty = false
        override var cloudChanges = 0L
    }

    @Test
    fun aSyncWithNothingSavedMeanwhileLeavesNothingToUpload() {
        val m = Memory()
        val book = CloudBookkeeping(m)
        book.changed()
        val t = book.begin()
        assertNull(t.known)
        assertTrue(t.dirty)
        assertFalse(book.finished(t, 7))
        assertEquals(7L, m.cloudVersion)
        assertFalse(m.cloudDirty)
    }

    @Test
    fun aChangeSavedDuringASyncIsNotCountedAsUploaded() {
        val m = Memory()
        val book = CloudBookkeeping(m)
        book.reset(version = 3, upload = false)
        val t = book.begin()
        assertEquals(CloudBookkeeping.Ticket(3, false, 0), t)
        book.changed() // saved while the request was on its way
        assertTrue(book.finished(t, 4))
        assertTrue(m.cloudDirty)
        val next = book.begin()
        assertEquals(4L, next.known)
        assertTrue(next.dirty)
        assertFalse(book.finished(next, 5))
        assertFalse(m.cloudDirty)
    }

    @Test
    fun turningSyncOnForAnOpenVaultAsksForAnUpload() {
        val m = Memory().apply { cloudVersion = 9 }
        CloudBookkeeping(m).reset(version = null, upload = true)
        assertNull(m.cloudVersion)
        assertTrue(m.cloudDirty)
    }
}
