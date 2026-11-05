package com.credpivot.android

import android.content.Context
import org.json.JSONObject
import java.io.File

/** 系统填充页沿用 App 导入的语言包；资源名称映射为稳定语义 key。 */
internal class AndroidStrings(private val context: Context) {
    private var settingsStamp = -1L
    private var packStamp = -1L
    private var translations = JSONObject()
    private var locale = ""

    fun get(resource: Int, vararg arguments: Any): String {
        try {
            val settings = File(context.filesDir, ".credpivot/settings.json")
            if (settings.lastModified() != settingsStamp) {
                settingsStamp = settings.lastModified()
                locale = if (settings.isFile && settings.length() < 1024 * 1024) JSONObject(settings.readText()).optString("language", "zh-CN") else "zh-CN"
                packStamp = -1L; translations = JSONObject()
            }
            if (locale != "zh-CN" && Regex("^[a-zA-Z0-9_-]{1,64}$").matches(locale)) {
                val file = File(context.filesDir, ".credpivot/languages/$locale.json")
                if (file.lastModified() != packStamp) {
                    packStamp = file.lastModified(); translations = JSONObject()
                    if (file.isFile && file.length() <= 4 * 1024 * 1024) {
                        val pack = JSONObject(file.readText())
                        if (pack.optString("format") == "credpivot-language" && pack.optInt("version") == 2 && pack.optString("locale") == locale) {
                            translations = pack.optJSONObject("messages") ?: JSONObject()
                        }
                    }
                }
            }
            val name = context.resources.getResourceEntryName(resource).split('_').mapIndexed { index, value ->
                if (index == 0) value else value.replaceFirstChar { it.uppercaseChar() }
            }.joinToString("")
            val key = when (resource) {
                android.R.string.cancel -> "common.cancel"
                android.R.string.ok -> "common.continue"
                else -> "android.native.$name"
            }
            val translation = translations.optJSONObject(key)?.optString("translation").orEmpty()
            if (translation.isNotBlank()) {
                return Regex("\\{arg([1-9][0-9]*)}").replace(translation) { match ->
                    arguments.getOrNull(match.groupValues[1].toInt() - 1)?.toString() ?: match.value
                }
            }
        } catch (_: Exception) { /* 语言资源损坏不能阻止解锁；回退内置文案。 */ }
        return context.getString(resource, *arguments)
    }
}
