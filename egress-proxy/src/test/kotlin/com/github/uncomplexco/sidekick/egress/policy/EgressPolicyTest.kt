package com.github.uncomplexco.sidekick.egress.policy

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class EgressPolicyTest {
    private val jira =
        EgressRule(
            id = "jira",
            host = "*.atlassian.net",
            action = EgressAction.TERMINATE,
            pathPrefix = "/rest/",
            credentialRef = "jira-token",
            header = "Authorization",
            valueTemplate = "Bearer {{token}}",
        )
    private val github =
        EgressRule(
            id = "github",
            host = "api.github.com",
            action = EgressAction.TERMINATE,
            credentialRef = "github-token",
            header = "Authorization",
            valueTemplate = "token {{token}}",
        )
    private val npm = EgressRule(id = "npm", host = "registry.npmjs.org", action = EgressAction.TUNNEL)

    private val policy = EgressPolicy(listOf(jira, github, npm), defaultAction = EgressAction.DENY)

    @Test
    fun `exact host match`() {
        assertEquals(EgressAction.TERMINATE, policy.decideConnect("api.github.com"))
        assertEquals(EgressAction.TUNNEL, policy.decideConnect("registry.npmjs.org"))
    }

    @Test
    fun `wildcard matches subdomains but not apex`() {
        assertEquals(EgressAction.TERMINATE, policy.decideConnect("acme.atlassian.net"))
        assertEquals(EgressAction.TERMINATE, policy.decideConnect("deep.acme.atlassian.net"))
        assertEquals(EgressAction.DENY, policy.decideConnect("atlassian.net"))
    }

    @Test
    fun `unmatched host falls through to default`() {
        assertEquals(EgressAction.DENY, policy.decideConnect("evil.example.com"))
        assertEquals(
            EgressAction.TUNNEL,
            EgressPolicy(listOf(github), defaultAction = EgressAction.TUNNEL).decideConnect("other.com"),
        )
    }

    @Test
    fun `host match is case-insensitive and strips port`() {
        assertEquals(EgressAction.TERMINATE, policy.decideConnect("API.GitHub.com:443"))
    }

    @Test
    fun `matchRequest honors path prefix`() {
        assertEquals("jira", policy.matchRequest("acme.atlassian.net", "/rest/api/2/issue")?.id)
        assertNull(policy.matchRequest("acme.atlassian.net", "/wiki/spaces"))
    }

    @Test
    fun `first matching rule wins`() {
        val broad = EgressRule(id = "broad", host = "*.atlassian.net", action = EgressAction.TUNNEL)
        val ordered = EgressPolicy(listOf(jira, broad))
        // /rest/ path -> jira (declared first); other path -> broad tunnel
        assertEquals("jira", ordered.matchRequest("acme.atlassian.net", "/rest/x")?.id)
        assertEquals("broad", ordered.matchRequest("acme.atlassian.net", "/other")?.id)
    }

    @Test
    fun `terminate rule requires injection fields`() {
        assertFailsWith<IllegalArgumentException> {
            EgressRule(id = "bad", host = "x.com", action = EgressAction.TERMINATE)
        }
        assertFailsWith<IllegalArgumentException> {
            EgressRule(
                id = "bad",
                host = "x.com",
                action = EgressAction.TERMINATE,
                credentialRef = "t",
                header = "Authorization",
                valueTemplate = "Bearer no-placeholder",
            )
        }
    }

    @Test
    fun `default action cannot be terminate`() {
        assertFailsWith<IllegalArgumentException> {
            EgressPolicy(emptyList(), defaultAction = EgressAction.TERMINATE)
        }
    }
}
