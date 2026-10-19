.PHONY: rust-build rust-agent rust-host rust-ffi rust-dev rust-check

## 编译整个 Rust workspace（默认 release）
rust-build:
	cd $(ROOT) && $(CARGO) build $(CARGO_BUILD_FLAGS)

rust-dev:
	$(MAKE) CARGO_PROFILE=debug rust-build

rust-agent:
	cd $(ROOT) && $(CARGO) build $(CARGO_BUILD_FLAGS) -p credpivot-agent

rust-host:
	cd $(ROOT) && $(CARGO) build $(CARGO_BUILD_FLAGS) -p credpivot-native-host

rust-ffi:
	cd $(ROOT) && $(CARGO) build $(CARGO_BUILD_FLAGS) -p credpivot-ffi

rust-check:
	cd $(ROOT) && $(CARGO) check --workspace

rust-test:
	cd $(ROOT) && $(CARGO) test -p credpivot-agent
