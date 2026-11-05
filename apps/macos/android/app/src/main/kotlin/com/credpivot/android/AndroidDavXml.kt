package com.credpivot.android

import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

internal object AndroidDavXml {
    fun parse(bytes: ByteArray): List<Map<String, Any>> {
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            isExpandEntityReferences = false
        }
        val builder = factory.newDocumentBuilder()
        builder.setErrorHandler(object : org.xml.sax.ErrorHandler {
            override fun warning(e: org.xml.sax.SAXParseException) { throw e }
            override fun error(e: org.xml.sax.SAXParseException) { throw e }
            override fun fatalError(e: org.xml.sax.SAXParseException) { throw e }
        })
        val document = builder.parse(ByteArrayInputStream(bytes))
        val root = document.documentElement
        if (root.namespaceURI != "DAV:" || root.localName != "multistatus") throw AgentFailure("sync.errors.directory", "WebDAV 目录响应无效")
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
