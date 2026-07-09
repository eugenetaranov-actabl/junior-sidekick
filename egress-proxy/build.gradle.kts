plugins {
    `java-library`
    kotlin("jvm")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

val nettyVersion = "4.1.115.Final"
val bouncyCastleVersion = "1.80"

dependencies {
    api("io.netty:netty-handler:$nettyVersion")
    api("io.netty:netty-codec-http:$nettyVersion")

    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcpkix-jdk18on:$bouncyCastleVersion")
    implementation("org.slf4j:slf4j-api:2.0.16")

    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
