/// 将字节数格式化为简短可读文案（如 128 MB、1.2 GB）。
String formatResidentMemory(int bytes) {
  if (bytes <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  var value = bytes.toDouble();
  var unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  final int digits;
  if (unit <= 1) {
    digits = 0;
  } else if (value >= 100) {
    digits = 0;
  } else if (value >= 10) {
    digits = 1;
  } else {
    digits = 2;
  }
  final n = value.toStringAsFixed(digits);
  return '$n ${units[unit]}';
}
