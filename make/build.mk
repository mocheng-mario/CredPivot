.PHONY: build-all build-all-debug build-all-release

# 两端共用 Flutter 工程及构建目录，使用顺序递归调用，避免 make -j 引发产物覆盖。
# 聚合构建只生成产物，不替换 ~/.credpivot 下正在使用的开发版辅助程序。
build-all:
	@test -f "$(MACOS_APP_DIR)/android/key.properties" || (echo "请先配置 apps/macos/android/key.properties 发布签名，或使用 make build-all-debug。" >&2; exit 1)
	$(MAKE) build-all-debug
	$(MAKE) build-all-release

build-all-debug:
	$(MAKE) INSTALL_DEV_ARTIFACTS=0 macos-build-debug
	$(MAKE) android-build-debug
	$(MAKE) CARGO_PROFILE=debug rust-cli
	@echo "Debug CLI: $(CARGO_TARGET_DIR)/debug/credpivot-cli"

build-all-release:
	@test -f "$(MACOS_APP_DIR)/android/key.properties" || (echo "请先配置 apps/macos/android/key.properties 发布签名，或使用 make build-all-debug。" >&2; exit 1)
	$(MAKE) macos-build-release
	$(MAKE) android-build-release
	$(MAKE) CARGO_PROFILE=release rust-cli
	$(MAKE) release-extension
	@echo "Release CLI: $(CARGO_TARGET_DIR)/release/credpivot-cli"
