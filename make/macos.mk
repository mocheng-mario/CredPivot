.PHONY: macos-bootstrap macos-pub-get macos-sync-artifacts macos-build macos-build-debug macos-build-release

## 首次：flutter create + Rust 产物 + debug 构建（等同 scripts/bootstrap-macos.sh）
macos-bootstrap:
	$(ROOT)/scripts/bootstrap-macos.sh

macos-pub-get:
	cd $(MACOS_APP_DIR) && $(FLUTTER) pub get

## 将 Rust 静态库与 native-host 复制到 Runner（需先 make rust-ffi rust-host）
macos-sync-artifacts: rust-ffi rust-host
	@test -f $(RUST_LIB_FFI) || (echo "missing $(RUST_LIB_FFI); run make rust-ffi" >&2; exit 1)
	@test -f $(RUST_HOST_BIN) || (echo "missing $(RUST_HOST_BIN); run make rust-host" >&2; exit 1)
	mkdir -p $(MACOS_RUNNER)
	cp $(RUST_LIB_FFI) $(MACOS_RUNNER)/
	cp $(RUST_HOST_BIN) $(MACOS_RUNNER)/credpivot-native-host
	chmod +x $(MACOS_RUNNER)/credpivot-native-host
	@if [ -f $(MACOS_APP_DIR)/macos/Runner.xcodeproj/project.pbxproj ]; then \
		$(ROOT)/scripts/patch-macos-xcode.sh; \
	fi

macos-build-debug:
	$(MAKE) CARGO_PROFILE=debug macos-sync-artifacts
	cd $(MACOS_APP_DIR) && $(FLUTTER) build macos --debug

macos-build-release:
	$(MAKE) CARGO_PROFILE=release macos-sync-artifacts
	cd $(MACOS_APP_DIR) && $(FLUTTER) build macos --release

macos-build: macos-build-debug
