/// 下拉框 / 关联字段：ID 在候选列表中不存在时视为无效（已删除等）。
String? dropdownValueIfPresent(
  String? id,
  List<Map<String, dynamic>> pool, {
  String idKey = 'id',
}) {
  if (id == null || id.isEmpty) return null;
  for (final row in pool) {
    if (row[idKey] == id) return id;
  }
  return null;
}

bool staleLinkWasCleared(String? raw, String? resolved) =>
    raw != null && raw.isNotEmpty && resolved == null;
