package com.github.uncomplexco.sidekick.sandbox.service

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertTrue

class NftablesJailTest {
    @Test
    fun `ruleset restricts the sandbox uid to only the proxy`() {
        val ruleset = NftablesJail.render(sandboxUid = 6000, proxyUid = 1000, listenAddress = "127.0.0.1", proxyPort = 8888)

        // Clean recreate for idempotency.
        assertContains(ruleset, "add table inet sidekick_egress")
        assertContains(ruleset, "delete table inet sidekick_egress")
        // Proxy uid stays open; sandbox uid may reach only the proxy addr:port, then everything else drops.
        assertContains(ruleset, "meta skuid 1000 accept")
        assertContains(ruleset, "meta skuid 6000 ip daddr 127.0.0.1 tcp dport 8888 accept")
        assertContains(ruleset, "meta skuid 6000 ct state established,related accept")
        assertTrue(ruleset.trimEnd().endsWith("meta skuid 6000 drop\n    }\n}") || ruleset.contains("meta skuid 6000 drop"))
    }
}
