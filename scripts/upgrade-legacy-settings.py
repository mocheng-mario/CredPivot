"""由独立升级 CLI 调用；只返回计数，明文配置不进入报告。"""
import copy
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from pathlib import Path


class UpgradeError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise UpgradeError(code)


def read_bytes(file, limit=4 * 1024 * 1024):
    require(not file.is_symlink() and file.is_file(), "local_file_not_regular")
    require(file.stat().st_size <= limit, "local_file_too_large")
    return file.read_bytes()


def read_json(file, default=None):
    require(not file.is_symlink(), "local_file_not_regular")
    return json.loads(read_bytes(file)) if file.exists() else copy.deepcopy(default)


def preferences():
    require(sys.platform == "darwin", "macos_settings_check_required")
    result = subprocess.run(["/usr/bin/defaults", "export", "com.credpivot.macos", "-"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode:
        file = Path.home() / "Library/Preferences/com.credpivot.macos.plist"
        require(not file.exists(), "preferences_export_failed")
        return {}, None
    data = plistlib.loads(result.stdout)
    require(isinstance(data, dict), "preferences_not_dictionary")
    return data, result.stdout


def legacy_probe_count(journal, android=False):
    require(isinstance(journal, dict), "probe_journal_invalid")
    result = 0
    for entries in journal.values():
        require(isinstance(entries, list if android else dict), "probe_journal_invalid")
        for name in entries:
            require(isinstance(name, str), "probe_journal_invalid")
            if re.fullmatch(r"\.credpivot-test-[0-9a-fA-F-]{36}", name):
                result += 1
    return result


def prepare(request):
    runtime = Path.home() / ".credpivot"
    settings_file = runtime / "settings.json"
    settings = read_json(settings_file, {})
    require(isinstance(settings, dict) and settings.get("version", 1) == 1, "settings_invalid")
    prefs, prefs_bytes = preferences()
    updated, updated_prefs = copy.deepcopy(settings), copy.deepcopy(prefs)
    counts = {"8_settings_file_missing": int(not settings_file.exists()),
              "8_missing_preferences": 0, "8_split_config_files": 0,
              "8_legacy_shortcut_field": int("shortcut_copy" in settings),
              "8_legacy_terminal_keys": 0, "9_legacy_webdav_settings": 0,
              "9_legacy_probe_paths": 0, "10_retired_language_keys": 0,
              "10_v1_language_packs": 0}
    legacy_files = []
    for name, field in [("log_level", "log_level"), ("extension_gate_idle_secs", "browser_idle_seconds"),
                        ("active_vault_dir", "vault_directory"), ("chrome_extension_id", "chrome_extension_id")]:
        file = runtime / name
        if not file.exists():
            continue
        counts["8_split_config_files"] += 1
        value = read_bytes(file, 16384).decode().strip()
        if settings.get(field) is None:
            if name == "extension_gate_idle_secs":
                require(value.isdigit() and 60 <= int(value) <= 1800 and int(value) % 60 == 0, "legacy_browser_timeout_invalid")
                value = int(value)
            elif name == "log_level":
                require(value in ("debug", "info", "warn", "error"), "legacy_log_level_invalid")
            elif name == "active_vault_dir":
                require(Path(value).is_absolute() and (Path(value) / "vault.json").is_file(), "legacy_vault_directory_invalid")
            else:
                require(not value or re.fullmatch("[a-p]{32}", value), "legacy_extension_id_invalid")
            updated[field] = value
        legacy_files.append(file)

    manual_required = False
    for field in ("terminal_app_path", "chrome_extension_id", "launch_at_login"):
        if settings.get(field) is not None:
            continue
        counts["8_missing_preferences"] += 1
        if field == "terminal_app_path":
            value = prefs.get("credpivot.terminal.app_path", "")
            if not value and prefs.get("credpivot.terminal.app"):
                preset = prefs["credpivot.terminal.app"]
                mapping = {"terminal": "/System/Applications/Utilities/Terminal.app",
                           "iterm": "/Applications/iTerm.app", "warp": "/Applications/Warp.app"}
                require(preset in mapping, "legacy_terminal_preset_unknown")
                value = mapping[preset]
            require(isinstance(value, str) and (not value or (value.startswith("/") and value.endswith(".app"))), "legacy_terminal_path_invalid")
            updated[field] = value
        elif field == "chrome_extension_id":
            if updated.get(field) is None:
                updated[field] = ""
        else:
            choice = request.get("launch_at_login")
            require(choice is None or isinstance(choice, bool), "launch_at_login_parameter_invalid")
            if choice is None:
                manual_required = True
            else:
                updated[field] = choice
    updated.setdefault("version", 1)
    if settings.get("shortcut_copy") == "command+shift+c":
        if settings.get("shortcut_search") in ("command+shift+space", "command+option+space"):
            updated["shortcut_search"] = "command+k"
        if settings.get("shortcut_lock") == "command+shift+l":
            updated["shortcut_lock"] = "command+l"
    updated.pop("shortcut_copy", None)
    for name in ("credpivot.terminal.app_path", "credpivot.terminal.app"):
        if name in updated_prefs:
            counts["8_legacy_terminal_keys"] += 1
            del updated_prefs[name]

    webdav = updated.get("webdav")
    if webdav is not None:
        require(isinstance(webdav, dict), "webdav_settings_invalid")
        legacy_webdav = not webdav.get("server_url") or not webdav.get("provider") or "directory" not in webdav
        if not webdav.get("server_url"):
            require(isinstance(webdav.get("root"), str) and not webdav.get("directory"), "legacy_webdav_settings_invalid")
            address = urlsplit(webdav["root"])
            require(address.scheme == "https" and address.hostname and not address.username and not address.password
                    and not address.query and not address.fragment and webdav["root"].endswith("/"), "legacy_webdav_settings_invalid")
            # 保留最终 root 和 location，不能改动钥匙串/同步绑定的身份。
            webdav["server_url"], webdav["directory"] = webdav["root"], ""
        if not webdav.get("provider"):
            webdav["provider"] = "custom"
        webdav.setdefault("directory", "")
        counts["9_legacy_webdav_settings"] = int(legacy_webdav)
    counts["9_legacy_probe_paths"] = legacy_probe_count(prefs.get("credpivot.webdav.pendingProbes", {}))
    android_journal = read_json(runtime / "webdav-probes.json")
    if android_journal is not None:
        require(isinstance(android_journal, dict) and android_journal.get("version") == 1, "probe_journal_invalid")
        counts["9_legacy_probe_paths"] += legacy_probe_count(android_journal.get("pending"), android=True)

    keys = set(request["catalog_keys"])
    packs = []
    language_dir = runtime / "languages"
    require(not language_dir.is_symlink(), "language_directory_is_symlink")
    for file in sorted(language_dir.glob("*.json")):
        pack = read_json(file)
        require(isinstance(pack, dict), "language_pack_invalid")
        if pack.get("version") == 1:
            counts["10_v1_language_packs"] += 1
            continue  # 不猜测已不支持的 v1 译文格式。
        require(pack.get("format") == "credpivot-language" and pack.get("version") == 2
                and isinstance(pack.get("messages"), dict), "language_pack_invalid")
        retired = set(pack["messages"]) - keys
        counts["10_retired_language_keys"] += len(retired)
        if retired:
            clean = copy.deepcopy(pack)
            for key in retired:
                del clean["messages"][key]
            packs.append((file, clean))
    return {"counts": counts, "manual_required": manual_required,
            "pending_external_cleanup": counts["9_legacy_probe_paths"] > 0,
            "settings": updated, "settings_changed": updated != settings or not settings_file.exists(),
            "preferences": updated_prefs, "preferences_changed": updated_prefs != prefs,
            "preferences_backup": prefs_bytes, "legacy_files": legacy_files, "packs": packs}


def store_new(file, data):
    with file.open("xb") as out:
        os.chmod(file, 0o600)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def atomic_json(file, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".legacy-upgrade-", dir=file.parent)
    try:
        with os.fdopen(descriptor, "wb") as out:
            out.write((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, file)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    os.umask(0o077)
    request = json.load(sys.stdin)
    plan = prepare(request)
    if request.get("apply"):
        require(not plan["manual_required"], "launch_at_login_requires_explicit_parameter")
        backup = Path(request["backup_dir"])
        require(backup.is_dir() and not backup.is_symlink(), "backup_directory_invalid")
        runtime = Path.home() / ".credpivot"
        # 所有受影响配置先备份，随后逐个原子替换。备份留在保险库私有升级目录。
        if plan["settings_changed"] and (runtime / "settings.json").exists():
            store_new(backup / "settings.json", read_bytes(runtime / "settings.json"))
        for file in plan["legacy_files"]:
            store_new(backup / ("legacy-" + file.name), read_bytes(file, 16384))
        if plan["packs"]:
            (backup / "languages").mkdir(mode=0o700)
        for file, _ in plan["packs"]:
            store_new(backup / "languages" / file.name, read_bytes(file))
        if plan["preferences_changed"] and plan["preferences_backup"] is not None:
            store_new(backup / "preferences.plist", plan["preferences_backup"])
        if plan["settings_changed"]:
            atomic_json(runtime / "settings.json", plan["settings"])
        if plan["preferences_changed"]:
            file = backup / "preferences-upgraded.plist"
            store_new(file, plistlib.dumps(plan["preferences"]))
            result = subprocess.run(["/usr/bin/defaults", "import", "com.credpivot.macos", str(file)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            require(result.returncode == 0, "preferences_import_failed_backup_retained")
        for file, pack in plan["packs"]:
            atomic_json(file, pack)
        for file in plan["legacy_files"]:
            file.unlink()
        plan = prepare(request)
    print(json.dumps({"ok": True, "counts": plan["counts"], "manual_required": plan["manual_required"],
                      "pending_external_cleanup": plan["pending_external_cleanup"], "android_device_data_checked": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except UpgradeError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        sys.exit(1)
    except Exception:
        # 不打印异常正文/traceback，防止包含路径、端点或配置字段值。
        print(json.dumps({"ok": False, "error": "local_upgrade_failed_backup_retained_if_created"}))
        sys.exit(1)
