.PHONY: chrome-info chrome-host-manifest chrome-pack firefox-pack

## 打印扩展目录与加载方式
chrome-info:
	@echo "Chrome 扩展目录: $(CHROME_EXT_DIR)"
	@echo "在 chrome://extensions 开启开发者模式后「加载已解压的扩展程序」"
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

## Chrome 与 Firefox 分开打包。源目录清单仍同时包含两边字段，供开发时直接加载。
chrome-pack:
	bash "$(ROOT)/scripts/package-release.sh" chrome "$(CHROME_EXT_DIR)"

firefox-pack:
	bash "$(ROOT)/scripts/package-release.sh" firefox "$(CHROME_EXT_DIR)"
