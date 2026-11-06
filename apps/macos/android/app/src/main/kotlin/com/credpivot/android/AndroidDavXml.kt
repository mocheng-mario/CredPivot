package com.credpivot.android

import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.xmlpull.v1.XmlPullParser

internal object AndroidDavXml {
    fun parse(bytes: ByteArray): List<Map<String, Any>> {
        // Android DOM 不支持 Apache 的禁用 DTD/外部实体开关；先用系统 PullParser
        // 拒绝 DTD，再构建 DOM，不能忽略不支持的安全开关后继续解析不可信响应。
        if (bytes.size > 4 * 1024 * 1024) throw AgentFailure("sync.errors.directory", "WebDAV 目录响应过大")
        val preflight = android.util.Xml.newPullParser()
        preflight.setFeature(XmlPullParser.FEATURE_PROCESS_DOCDECL, false)
        preflight.setInput(ByteArrayInputStream(bytes), null)
        var event = preflight.eventType
        while (event != XmlPullParser.END_DOCUMENT) {
            if (event == XmlPullParser.DOCDECL || preflight.depth > 128) {
                throw AgentFailure("sync.errors.directory", "WebDAV 目录响应包含不允许的 XML 结构")
            }
            event = preflight.nextToken()
        }
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
        }
        val builder = factory.newDocumentBuilder()
        builder.setEntityResolver { _, _ -> throw org.xml.sax.SAXException("External entities are not allowed") }
        builder.setErrorHandler(object : org.xml.sax.ErrorHandler {
            override fun warning(e: org.xml.sax.SAXParseException) { throw e }
            override fun error(e: org.xml.sax.SAXParseException) { throw e }
            override fun fatalError(e: org.xml.sax.SAXParseException) { throw e }
        })
        val document = builder.parse(ByteArrayInputStream(bytes))
        val root = document.documentElement
        if (root.namespaceURI != "DAV:" || root.localName != "multistatus") throw AgentFailure("sync.errors.directory", "WebDAV 目录响应无效")
        // 不能把被截断或带错误的列表当作空目录，否则集合 DELETE 可能误删未列出的内容。
        if (root.getElementsByTagNameNS("DAV:", "error").length > 0 ||
            root.getElementsByTagNameNS("DAV:", "number-of-matches-within-limits").length > 0) {
            throw AgentFailure("sync.cleanup.incomplete", "WebDAV 目录响应不完整，已停止操作")
        }
        val rows = root.getElementsByTagNameNS("DAV:", "response")
        return (0 until rows.length).map { index ->
            val response = rows.item(index) as Element
            val href = response.getElementsByTagNameNS("DAV:", "href").item(0)?.textContent?.trim()
                ?: throw AgentFailure("sync.errors.directory", "WebDAV 目录响应缺少路径")
            val properties = response.getElementsByTagNameNS("DAV:", "propstat")
            val values = mutableMapOf<String, Any>("href" to href, "collection" to false)
            for (i in 0 until properties.length) {
                val prop = properties.item(i) as Element
                val status = prop.getElementsByTagNameNS("DAV:", "status").item(0)?.textContent.orEmpty()
                if (status.trim().split(Regex("\\s+")).getOrNull(1) != "200") continue
                // 同一资源的属性可以分布在多个 propstat 中，后一个分组不能抹掉目录标记。
                if (prop.getElementsByTagNameNS("DAV:", "collection").length > 0) values["collection"] = true
                for (name in listOf("getetag", "getlastmodified")) {
                    prop.getElementsByTagNameNS("DAV:", name).item(0)?.textContent?.let { values[name] = it.trim() }
                }
            }
            values
        }
    }
}
