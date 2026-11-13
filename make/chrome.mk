.PHONY: chrome-info chrome-host-manifest chrome-pack firefox-unpacked firefox-pack

FIREFOX_UNPACKED := $(ROOT)/dist/firefox-unpacked

## 打印扩展目录与加载方式
chrome-info:
	@echo "Chrome 扩展目录: $(CHROME_EXT_DIR)"
	@echo "在 chrome://extensions 开启开发者模式后「加载已解压的扩展程序」"
	@echo "Firefox 临时加载: make firefox-unpacked，然后在 about:debugging 加载 $(FIREFOX_UNPACKED)/manifest.json"
	@echo "Native Host 名: com.credpivot.chrome.m0"
	@echo "清单模板: $(CHROME_EXT_DIR)/native-messaging-host-m0.json"

## 将 native-host 路径写入用户 Chrome NativeMessagingHosts（需已 make rust-host）
chrome-host-manifest: rust-host
	@HOST="$(RUST_HOST_BIN)"; \
	DIR="$$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"; \
	mkdir -p "$$DIR"; \
	printf '%s\n' '{' \
	  '  "name": "com.credpivot.chrome.m0",' \
	  '  "description": "CredPivot M0 Native Messaging Host",' \
	  "  \"path\": \"$$HOST\"," \
	  '  "type": "stdio",' \
	  '  "allowed_origins": ["chrome-extension://REPLACE_WITH_EXTENSION_ID/"]' \
	  '}' > "$$DIR/com.credpivot.chrome.m0.json"; \
	echo "已写入 $$DIR/com.credpivot.chrome.m0.json（请替换 allowed_origins 中的扩展 ID）"

## Chrome 打包共用文件和 Chrome 清单。Firefox 使用自己的清单。
chrome-pack:
	bash "$(ROOT)/scripts/package-release.sh" chrome "$(CHROME_EXT_DIR)"

firefox-unpacked:
	rm -rf "$(FIREFOX_UNPACKED)"
	mkdir -p "$(FIREFOX_UNPACKED)"
	cp -R "$(CHROME_EXT_DIR)/." "$(FIREFOX_UNPACKED)/"
	rm -f "$(FIREFOX_UNPACKED)/manifest.json" "$(FIREFOX_UNPACKED)/native-messaging-host-m0.json"
	cp "$(ROOT)/apps/firefox-extension/manifest.json" "$(FIREFOX_UNPACKED)/manifest.json"
	@echo "Firefox 临时加载: $(FIREFOX_UNPACKED)/manifest.json"

firefox-pack: firefox-unpacked
	bash "$(ROOT)/scripts/package-release.sh" firefox "$(FIREFOX_UNPACKED)"
