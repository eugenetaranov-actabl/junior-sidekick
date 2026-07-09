package com.github.uncomplexco.sidekick.egress.cred

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SecretTest {
    @Test
    fun `renderInto substitutes the placeholder`() {
        val secret = Secret("s3cr3t")
        val rendered = secret.renderInto("Bearer {{token}}")
        assertEquals("Bearer s3cr3t", String(rendered))
    }

    @Test
    fun `renderInto requires the placeholder`() {
        assertFailsWith<IllegalArgumentException> { Secret("x").renderInto("Bearer no-placeholder") }
    }

    @Test
    fun `close zeroes the value and blocks further use`() {
        val secret = Secret("s3cr3t")
        secret.close()
        assertFailsWith<IllegalStateException> { secret.renderInto("Bearer {{token}}") }
    }

    @Test
    fun `wipe zeroes a rendered array`() {
        val rendered = "Bearer abc".toCharArray()
        Secret.wipe(rendered)
        assertTrue(rendered.all { it == '\u0000' })
    }

    @Test
    fun `config source returns independent copies`() {
        val source = ConfigCredentialSource.fromStrings(mapOf("jira-token" to "abc123"))
        val first = source.resolve("jira-token")!!
        val rendered = first.renderInto("Bearer {{token}}")
        assertEquals("Bearer abc123", String(rendered))
        first.close() // closing our copy must not destroy the source's stored value

        val second = source.resolve("jira-token")!!
        assertEquals("Bearer abc123", String(second.renderInto("Bearer {{token}}")))

        assertNull(source.resolve("missing"))
    }
}
