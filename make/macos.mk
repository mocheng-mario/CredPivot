.PHONY: macos-bootstrap macos-pub-get macos-ensure-build-stamp macos-write-build-stamp macos-sync-artifacts macos-build macos-build-debug macos-build-release macos-install

## 首次：flutter create + Rust 产物 + debug 构建（等同 scripts/bootstrap-macos.sh）
macos-bootstrap:
	$(ROOT)/scripts/bootstrap-macos.sh

macos-ensure-build-stamp:
	@test -f $(MACOS_APP_DIR)/lib/build_stamp.dart || cp $(MACOS_APP_DIR)/lib/build_stamp.dart.example $(MACOS_APP_DIR)/lib/build_stamp.dart

macos-pub-get: macos-ensure-build-stamp
	cd $(MACOS_APP_DIR) && $(FLUTTER) pub get

## 将 Rust 静态库与 native-host 复制到 Runner（需先 make rust-ffi rust-host）
macos-sync-artifacts: rust-ffi rust-host rust-askpass
	@test -f $(RUST_LIB_FFI) || (echo "missing $(RUST_LIB_FFI); run make rust-ffi" >&2; exit 1)
	@test -f $(RUST_HOST_BIN) || (echo "missing $(RUST_HOST_BIN); run make rust-host" >&2; exit 1)
	@test -f $(RUST_ASKPASS_BIN) || (echo "missing $(RUST_ASKPASS_BIN); run make rust-askpass" >&2; exit 1)
	@test -f $(RUST_GIT_SSH_BIN) || (echo "missing $(RUST_GIT_SSH_BIN); run make rust-askpass" >&2; exit 1)
	@test -f $(RUST_CONNECT_BIN) || (echo "missing $(RUST_CONNECT_BIN); run make rust-askpass" >&2; exit 1)
	mkdir -p $(MACOS_RUNNER)
	cp $(RUST_LIB_FFI) $(MACOS_RUNNER)/
	cp $(RUST_HOST_BIN) $(MACOS_RUNNER)/credpivot-native-host
	chmod +x $(MACOS_RUNNER)/credpivot-native-host
	cp $(RUST_ASKPASS_BIN) $(MACOS_RUNNER)/credpivot-askpass
	chmod +x $(MACOS_RUNNER)/credpivot-askpass
	cp $(RUST_GIT_SSH_BIN) $(MACOS_RUNNER)/credpivot-git-ssh
	chmod +x $(MACOS_RUNNER)/credpivot-git-ssh
	cp $(RUST_CONNECT_BIN) $(MACOS_RUNNER)/credpivot-connect
	chmod +x $(MACOS_RUNNER)/credpivot-connect
	rm -rf $(MACOS_RUNNER)/credpivot-chrome-extension
	cp -R $(CHROME_EXT_DIR) $(MACOS_RUNNER)/credpivot-chrome-extension
	cp $(ROOT)/apps/firefox-extension/manifest.json $(MACOS_RUNNER)/credpivot-firefox-manifest.json
	cp $(ROOT)/assets/ssh-expect-pass.exp $(MACOS_RUNNER)/ssh-expect-pass.exp
	chmod 755 $(MACOS_RUNNER)/ssh-expect-pass.exp
ifeq ($(INSTALL_DEV_ARTIFACTS),1)
	@mkdir -p $(HOME)/.credpivot
	@echo "$(RUST_HOST_BIN)" > $(HOME)/.credpivot/native_host_binary.path
	@echo "$(CHROME_EXT_DIR)" > $(HOME)/.credpivot/chrome_extension_dir.path
	rm -rf $(HOME)/.credpivot/chrome-extension
	cp -R $(CHROME_EXT_DIR) $(HOME)/.credpivot/chrome-extension
	@echo "$(RUST_ASKPASS_BIN)" > $(HOME)/.credpivot/askpass_binary.path
	cp $(RUST_ASKPASS_BIN) $(HOME)/.credpivot/credpivot-askpass
	chmod 755 $(HOME)/.credpivot/credpivot-askpass
	shasum -a 256 $(HOME)/.credpivot/credpivot-askpass | awk '{print $$1}' > $(HOME)/.credpivot/askpass.sha256
	@echo "$(RUST_ASKPASS_BIN)" > $(HOME)/.credpivot/askpass_trusted.path
	cp $(ROOT)/assets/ssh-expect-pass.exp $(HOME)/.credpivot/ssh-expect-pass.exp
	chmod 755 $(HOME)/.credpivot/ssh-expect-pass.exp
	@echo "$(ROOT)/assets/ssh-expect-pass.exp" > $(HOME)/.credpivot/expect_script.source.path
endif
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
	$(MAKE) CARGO_PROFILE=release INSTALL_DEV_ARTIFACTS=0 macos-sync-artifacts
	cd $(MACOS_APP_DIR) && $(FLUTTER) build macos --release --build-name $(MACOS_BUILD_NAME)
	@echo "Release: $(MACOS_APP_DIR)/build/macos/Build/Products/Release/credpivot_macos.app"
	@echo "构建不会退出当前 App；若正在运行 Debug，请先用 Cmd+Q 退出，再打开上述 Release。"
	@echo "安装到应用程序：make macos-install；生成拖拽安装包：make release-app"

macos-install: macos-build-release
	bash "$(ROOT)/scripts/install-macos.sh" "$(MACOS_APP_DIR)/build/macos/Build/Products/Release/credpivot_macos.app" "$(MACOS_INSTALL_DIR)"

macos-build: macos-build-debug
