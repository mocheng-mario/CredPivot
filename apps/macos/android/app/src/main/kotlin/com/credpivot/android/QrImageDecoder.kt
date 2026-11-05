package com.credpivot.android

import android.graphics.BitmapFactory
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.GenericMultipleBarcodeReader
import java.io.File

internal object QrImageDecoder {
    fun decode(file: File): List<String> {
        if (file.length() > 64L * 1024 * 1024) throw AgentFailure("qr_image_size", "二维码图片超过 64 MB 限制")
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) throw AgentFailure("qr_image", "无法读取该图片")
        // 默认值为 0；解码器会把它当 1，但这里先做了除法，必须显式初始化。
        val options = BitmapFactory.Options().apply { inSampleSize = 1; inMutable = true }
        while (bounds.outWidth / options.inSampleSize > 2400 || bounds.outHeight / options.inSampleSize > 2400) options.inSampleSize *= 2
        val bitmap = BitmapFactory.decodeFile(file.absolutePath, options) ?: throw AgentFailure("qr_image", "无法读取该图片")
        try {
            val pixels = IntArray(bitmap.width * bitmap.height)
            try {
                bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
                val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
                val hints = mapOf<DecodeHintType, Any>(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true)
                val reader = MultiFormatReader().apply { setHints(hints) }
                val found = try { GenericMultipleBarcodeReader(reader).decodeMultiple(BinaryBitmap(HybridBinarizer(source)), hints).toList() }
                    catch (_: com.google.zxing.NotFoundException) {
                        try { listOf(reader.decode(BinaryBitmap(HybridBinarizer(source.invert())), hints)) }
                        catch (_: com.google.zxing.NotFoundException) { emptyList() }
                    }
                return found.map { it.text }.filter { it.startsWith("otpauth://", true) && it.length <= 32768 }.distinct().take(20)
                    .ifEmpty { throw AgentFailure("qr_not_found", "未识别到 MFA 二维码，请使用清晰原图或粘贴 otpauth 链接") }
            } finally { pixels.fill(0) }
        } finally { bitmap.eraseColor(android.graphics.Color.TRANSPARENT); bitmap.recycle() }
    }
}
