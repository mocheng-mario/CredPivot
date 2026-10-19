.PHONY: sbom

## 生成 Rust SBOM 到 dist/sbom（需 cargo-cyclonedx）
sbom:
	$(ROOT)/scripts/generate-sbom.sh
