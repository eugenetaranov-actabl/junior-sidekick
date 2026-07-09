package com.github.uncomplexco.sidekick.egress.cred

/**
 * A credential value held in a [CharArray] rather than a [String] so it can be zeroed after use.
 *
 * Strings are immutable and may linger in the heap until GC (and can surface in heap dumps); a
 * [CharArray] lets us overwrite the contents deterministically once the value has been written to
 * the outbound request. Zeroing is best-effort (the JVM may still have copied the value elsewhere)
 * but it meaningfully shrinks the window in which the secret is readable.
 *
 * The value must never be logged, placed in a [String], or otherwise copied into an un-zeroable form.
 */
class Secret(
    private val value: CharArray,
) : AutoCloseable {
    @Volatile
    private var cleared = false

    constructor(value: String) : this(value.toCharArray())

    /**
     * Renders the header value from a template such as "Bearer {{token}}", substituting the secret
     * for the {{token}} placeholder. The returned [CharArray] is caller-owned and should be zeroed
     * after being written to the wire (see [wipe]).
     */
    fun renderInto(template: String): CharArray {
        check(!cleared) { "Secret has already been cleared" }
        val placeholder = PLACEHOLDER
        val idx = template.indexOf(placeholder)
        require(idx >= 0) { "value-template must contain $placeholder" }
        val prefix = template.substring(0, idx)
        val suffix = template.substring(idx + placeholder.length)
        val out = CharArray(prefix.length + value.size + suffix.length)
        prefix.toCharArray(out, 0)
        value.copyInto(out, prefix.length)
        suffix.toCharArray(out, prefix.length + value.size)
        return out
    }

    override fun close() {
        if (!cleared) {
            value.fill(ZERO)
            cleared = true
        }
    }

    companion object {
        const val PLACEHOLDER = "{{token}}"
        private const val ZERO = '\u0000'

        /** Zeroes a rendered header-value array once it has been written to the wire. */
        fun wipe(chars: CharArray) {
            chars.fill(ZERO)
        }
    }
}
