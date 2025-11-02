plugins {
    kotlin("jvm") version "2.2.10"
}

group = "io.github.hirsivaja"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    systemProperty("java.util.logging.config.file", "src/test/resources/logging.properties")
}

kotlin {
    jvmToolchain(21)
}
