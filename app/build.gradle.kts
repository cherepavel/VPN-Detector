plugins {
    id("com.android.application")
}

fun gitCommitHash(): String {
    return try {
        val process = ProcessBuilder("git", "rev-parse", "--short", "HEAD")
            .redirectErrorStream(true)
            .start()

        val result = process.inputStream.bufferedReader().use { it.readText() }.trim()
        val exitCode = process.waitFor()

        if (exitCode == 0 && result.isNotBlank()) result else "unknown"
    } catch (e: Exception) {
        "unknown"
    }
}

extensions.configure<com.android.build.api.dsl.ApplicationExtension> {
    namespace = "com.cherepavel.vpndetector"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.cherepavel.vpndetector"
        minSdk = 24
        targetSdk = 36
        versionCode = 2
        versionName = "0.0.2"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "GIT_HASH", "\"${gitCommitHash()}\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11
    }
}

dependencies {
    api(project(":detector"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
