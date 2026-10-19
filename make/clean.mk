.PHONY: clean-rust clean-flutter clean

clean-rust:
	cd $(ROOT) && $(CARGO) clean

clean-flutter:
	cd $(MACOS_APP_DIR) && $(FLUTTER) clean

clean: clean-rust clean-flutter
