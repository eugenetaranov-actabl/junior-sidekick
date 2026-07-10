plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "junior-sidekick"

include("core")
include("tools")
include("app")
