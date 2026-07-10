plugins {
    `java-library`
    kotlin("jvm")
    kotlin("plugin.spring")
    kotlin("plugin.serialization")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

dependencies {
    implementation(project(":core"))

    implementation(platform("org.springframework.boot:spring-boot-dependencies:4.0.7"))
    api("com.slack.api:slack-api-client:1.49.0")

    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework:spring-context")
    implementation("org.springframework:spring-web")
    implementation("org.jetbrains.kotlin:kotlin-reflect:2.3.20")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core")
    implementation("org.jsoup:jsoup:1.22.2")
    implementation("com.vladsch.flexmark:flexmark-html2md-converter:0.64.8")

    implementation("ai.koog:koog-agents:1.0.0")
    implementation("ai.koog:agents-mcp:1.0.0-beta-preview7")
    implementation("io.modelcontextprotocol:kotlin-sdk-client:0.13.0")
    implementation("io.modelcontextprotocol:kotlin-sdk-core:0.13.0")
    implementation("org.eclipse.jgit:org.eclipse.jgit:7.7.0.202606012155-r")
    implementation("org.eclipse.jgit:org.eclipse.jgit.ssh.apache:7.7.0.202606012155-r")

    testImplementation("org.springframework:spring-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
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
