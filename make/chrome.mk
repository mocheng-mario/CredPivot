.PHONY: chrome-info chrome-host-manifest chrome-pack

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

## 打包扩展。压缩包根目录就是 manifest.json，可直接在 Firefox 中从文件安装。
chrome-pack:
	@mkdir -p "$(ROOT)/dist"
	@version=$$(/usr/bin/plutil -extract version raw -o - "$(CHROME_EXT_DIR)/manifest.json"); \
	archive="$(ROOT)/dist/CredPivot-extension-$$version.xpi"; \
	rm -f "$$archive"; \
	cd "$(CHROME_EXT_DIR)" && zip -r -X "$$archive" . -x '*.DS_Store' -x '__MACOSX/*'; \
	echo "已生成 $$archive"
