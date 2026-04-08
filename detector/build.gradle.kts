plugins {
    id("com.android.library")
}

android {
    namespace = "com.cherepavel.vpndetector.detector"
    compileSdk = 36

    defaultConfig {
        minSdk = 24

        externalNativeBuild {
            cmake {
                cppFlags += ""
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
}
