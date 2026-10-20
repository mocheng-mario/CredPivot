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
	rm -rf $(MACOS_RUNNER)/credpivot-chrome-extension
	cp -R $(CHROME_EXT_DIR) $(MACOS_RUNNER)/credpivot-chrome-extension
	@mkdir -p $(HOME)/.credpivot
	@echo "$(RUST_HOST_BIN)" > $(HOME)/.credpivot/native_host_binary.path
	@echo "$(CHROME_EXT_DIR)" > $(HOME)/.credpivot/chrome_extension_dir.path
	rm -rf $(HOME)/.credpivot/chrome-extension
	cp -R $(CHROME_EXT_DIR) $(HOME)/.credpivot/chrome-extension
	@if [ -f $(MACOS_APP_DIR)/macos/Runner.xcodeproj/project.pbxproj ]; then \
		$(ROOT)/scripts/patch-macos-xcode.sh; \
	fi

macos-write-build-stamp:
	@STAMP="$$(date '+%Y-%m-%d %H:%M:%S') $$(cd $(ROOT) && git rev-parse --short HEAD 2>/dev/null || echo nogit) $$(openssl rand -hex 4)"; \
	printf '%s\n' "const String kCredPivotBuildStamp = '$$STAMP';" > $(MACOS_APP_DIR)/lib/build_stamp.dart; \
	echo "build stamp: $$STAMP"

macos-build-debug: macos-write-build-stamp
	$(MAKE) CARGO_PROFILE=debug macos-sync-artifacts
	cd $(MACOS_APP_DIR) && $(FLUTTER) build macos --debug

macos-build-release: macos-write-build-stamp
	$(MAKE) CARGO_PROFILE=release macos-sync-artifacts
	cd $(MACOS_APP_DIR) && $(FLUTTER) build macos --release

macos-build: macos-build-debug
