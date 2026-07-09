plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "junior-sidekick"

include("core")
include("egress-proxy")
include("sandbox-bwrap")
include("sandbox-service")
include("tools")
include("app")
