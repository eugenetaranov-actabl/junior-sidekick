package com.github.uncomplexco.sidekick.sandbox.service

import com.github.uncomplexco.sidekick.egress.policy.EgressAction
import com.typesafe.config.ConfigFactory
import io.ktor.server.config.HoconApplicationConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EgressServiceConfigTest {
    private fun parse(hocon: String): EgressServiceConfig? =
        EgressServiceConfig.fromApplicationConfig(HoconApplicationConfig(ConfigFactory.parseString(hocon)))

    @Test
    fun `absent or disabled egress yields null`() {
        assertNull(parse(""))
        assertNull(parse("egress { enabled = false }"))
    }

    @Test
    fun `parses rules and credentials`() {
        val config =
            parse(
                """
                egress {
                  enabled = true
                  listen-address = "127.0.0.1"
                  port = 0
                  default-action = deny
                  credentials = [ { ref = jira-token, value = "s3cr3t" } ]
                  rules = [
                    { id = jira, host = "*.atlassian.net", path-prefix = "/rest/", action = terminate,
                      credential-ref = jira-token, header = "Authorization", value-template = "Bearer {{token}}" },
                    { id = npm, host = "registry.npmjs.org", action = tunnel }
                  ]
                }
                """.trimIndent(),
            )!!

        assertEquals(EgressAction.DENY, config.defaultAction)
        assertEquals(2, config.rules.size)
        assertEquals("jira", config.rules[0].id)
        assertEquals(EgressAction.TERMINATE, config.rules[0].action)
        assertEquals("/rest/", config.rules[0].pathPrefix)
        assertEquals(EgressAction.TUNNEL, config.rules[1].action)
        assertEquals("s3cr3t", config.credentials["jira-token"])

        // Sanity: the parsed rules build a working policy.
        val policy = config.policy()
        assertEquals("jira", policy.matchRequest("acme.atlassian.net", "/rest/api")?.id)
        assertTrue(policy.decideConnect("registry.npmjs.org") == EgressAction.TUNNEL)
    }
}
