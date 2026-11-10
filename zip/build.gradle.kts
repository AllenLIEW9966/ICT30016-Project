plugins {
    id("org.jetbrains.kotlin.jvm") version "2.2.20"
    // The version is provided by the settings plugin in settings.gradle.kts.
    id("org.jetbrains.intellij.platform")
}

group = "com.codeshield"
version = providers.gradleProperty("pluginVersion").get()

kotlin {
    jvmToolchain(17)
}

dependencies {
    intellijPlatform {
        intellijIdeaCommunity("2025.1.6")
    }
    implementation("com.google.code.gson:gson:2.11.0")
}

intellijPlatform {
    pluginConfiguration {
        id = "com.codeshield.securecoding"
        name = "CodeShield AI"
        version = project.version.toString()
        ideaVersion {
            sinceBuild = "241"
            untilBuild = provider { null }
        }
        vendor {
            name = "CodeShield AI"
        }
    }
}
