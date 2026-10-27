# 仓库根目录（本文件位于 make/ 下）
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

# 与 Runner MACOSX_DEPLOYMENT_TARGET 一致，避免 SQLCipher 对象文件 SDK 版本与链接目标不一致。
export MACOSX_DEPLOYMENT_TARGET ?= 15.0

CARGO ?= cargo
FLUTTER ?= flutter
CARGO_TARGET_DIR ?= $(ROOT)/target
CARGO_PROFILE ?= release
INSTALL_DEV_ARTIFACTS ?= 1

MACOS_APP_DIR := $(ROOT)/apps/macos
APP_VERSION := $(shell awk '/^version: / {print $$2; exit}' $(MACOS_APP_DIR)/pubspec.yaml)
# CFBundleShortVersionString 使用数字版本，Beta 标识保留在下载文件名和 Cargo 版本中。
MACOS_BUILD_NAME := $(firstword $(subst -, ,$(firstword $(subst +, ,$(APP_VERSION)))))
MACOS_RUNNER := $(MACOS_APP_DIR)/macos/Runner
CHROME_EXT_DIR := $(ROOT)/apps/chrome-extension

ifeq ($(CARGO_PROFILE),debug)
  RUST_ARTIFACT_DIR := $(CARGO_TARGET_DIR)/debug
  CARGO_BUILD_FLAGS :=
else
  RUST_ARTIFACT_DIR := $(CARGO_TARGET_DIR)/$(CARGO_PROFILE)
  CARGO_BUILD_FLAGS := --profile $(CARGO_PROFILE)
endif

RUST_LIB_FFI := $(RUST_ARTIFACT_DIR)/libcredpivot_ffi.a
RUST_HOST_BIN := $(RUST_ARTIFACT_DIR)/credpivot-native-host
RUST_ASKPASS_BIN := $(RUST_ARTIFACT_DIR)/credpivot-askpass
