package com.github.uncomplexco.sidekick.egress.cred

/**
 * Resolves a logical credential reference (chosen by the matched egress rule) into a [Secret].
 *
 * The [credentialRef] is always supplied by the policy rule, never by anything parsed from the
 * intercepted request — nothing the sandboxed process sends can influence which secret is fetched.
 * This is the identity-binding discipline that keeps the injection un-spoofable; it is preserved
 * here so a later per-principal implementation is a backend swap, not a rewrite.
 */
fun interface CredentialSource {
    /** Returns the secret for [credentialRef], or null if no such credential is configured. */
    fun resolve(credentialRef: String): Secret?
}
