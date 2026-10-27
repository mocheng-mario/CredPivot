.PHONY: sbom release-cli release-app release-extension release

## 生成 Rust SBOM 到 dist/sbom（需 cargo-cyclonedx）
sbom:
	$(ROOT)/scripts/generate-sbom.sh

# CLI 独立下载，不复制进 Runner 或 App 包。
release-cli:
	$(MAKE) CARGO_PROFILE=release rust-cli
	bash $(ROOT)/scripts/package-release.sh cli "$(CARGO_TARGET_DIR)/release/credpivot-cli"

release-app: macos-build-release
	bash $(ROOT)/scripts/package-release.sh app "$(MACOS_APP_DIR)/build/macos/Build/Products/Release/credpivot_macos.app"

release-extension:
	bash $(ROOT)/scripts/package-release.sh extension "$(CHROME_EXT_DIR)"

release: release-app release-cli release-extension
