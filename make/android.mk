.PHONY: android-rust android-build-debug android-build-release

# Android 不使用桌面端的 native-host、askpass 或 CLI。
android-rust:
	CARGO="$(CARGO)" CARGO_PROFILE="$(CARGO_PROFILE)" CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" bash "$(ROOT)/scripts/build-android-rust.sh"

android-build-debug:
	$(MAKE) CARGO_PROFILE=debug android-rust
	cd "$(MACOS_APP_DIR)" && $(FLUTTER) build apk --debug --target lib/main_android.dart --target-platform android-arm64,android-x64
	@echo "APK: $(MACOS_APP_DIR)/build/app/outputs/flutter-apk/app-debug.apk"

android-build-release:
	@test -f "$(MACOS_APP_DIR)/android/key.properties" || (echo "请先配置 apps/macos/android/key.properties 发布签名；不能使用临时 Debug 密钥发布。" >&2; exit 1)
	$(MAKE) CARGO_PROFILE=release android-rust
	cd "$(MACOS_APP_DIR)" && $(FLUTTER) build apk --release --target lib/main_android.dart --target-platform android-arm64,android-x64
	@echo "APK: $(MACOS_APP_DIR)/build/app/outputs/flutter-apk/app-release.apk"
