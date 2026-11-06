import java.util.Properties

plugins {
    id("com.android.application")
    // Flutter 插件必须在 Android 插件之后应用；Kotlin 由 AGP 9 内置提供。
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.credpivot.android"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.credpivot.android"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = 28
        targetSdk = flutter.targetSdkVersion
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        ndk {
            // Flutter 默认包含 32 位 ARM；当前 Rust 库只提供这两种 64 位架构。
            abiFilters.clear()
            abiFilters.addAll(listOf("arm64-v8a", "x86_64"))
        }
        externalNativeBuild {
            cmake { arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON" }
        }
    }

    externalNativeBuild {
        cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" }
    }

    // Rust 库由独立 Cargo 脚本生成，必须显式打包，不能只让 CMake 链接它。
    sourceSets.getByName("main").jniLibs.srcDir("src/main/rustLibs")

    buildTypes {
        release {
            // 发布密钥由开发者保管；缺少配置时不回退到 Debug 签名。
            val signingFile = rootProject.file("key.properties")
            if (signingFile.exists()) {
                val properties = Properties().apply { signingFile.inputStream().use { load(it) } }
                signingConfig = signingConfigs.create("release") {
                    storeFile = rootProject.file(properties.getProperty("storeFile"))
                    storePassword = properties.getProperty("storePassword")
                    keyAlias = properties.getProperty("keyAlias")
                    keyPassword = properties.getProperty("keyPassword")
                }
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    // 离线识别 MFA 二维码，不把包含种子的图片交给网络服务。
    implementation("com.google.zxing:core:3.5.3")
    implementation("androidx.credentials:credentials:1.5.0")
}
