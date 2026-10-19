/// 解析 otpauth URI（支持路径中含空格、中文 issuer）。
class OtpauthParseResult {
  OtpauthParseResult({
    required this.issuer,
    required this.account,
    required this.secret,
  });

  final String issuer;
  final String account;
  final String secret;
}

String? _queryParam(String uri, String key) {
  final qIndex = uri.indexOf('?');
  if (qIndex < 0) return null;
  final query = uri.substring(qIndex + 1);
  for (final part in query.split('&')) {
    final eq = part.indexOf('=');
    if (eq <= 0) continue;
    final k = Uri.decodeComponent(part.substring(0, eq));
    if (k == key) {
      return Uri.decodeComponent(part.substring(eq + 1));
    }
  }
  return null;
}

OtpauthParseResult? parseOtpauthUri(String raw) {
  final t = raw.trim();
  if (!t.toLowerCase().startsWith('otpauth://')) return null;

  var secret = _queryParam(t, 'secret') ?? '';
  var issuer = _queryParam(t, 'issuer') ?? '';

  final pathStart = t.indexOf('/', 'otpauth://'.length);
  if (pathStart >= 0) {
    final qIndex = t.indexOf('?', pathStart);
    final path = Uri.decodeComponent(
      qIndex >= 0 ? t.substring(pathStart + 1, qIndex) : t.substring(pathStart + 1),
    );
    if (path.isNotEmpty) {
      final colon = path.lastIndexOf(':');
      if (colon > 0) {
        final pathIssuer = path.substring(0, colon);
        final account = path.substring(colon + 1);
        if (issuer.isEmpty) issuer = pathIssuer;
        return OtpauthParseResult(issuer: issuer, account: account, secret: secret);
      }
      return OtpauthParseResult(issuer: issuer, account: path, secret: secret);
    }
  }
  return OtpauthParseResult(issuer: issuer, account: '', secret: secret);
}

String? validateTotpSecretInput(String secret) {
  final s = secret.trim();
  if (s.isEmpty) return '请填写 TOTP 密钥';
  if (s.contains('{') || s.contains('}')) {
    return '密钥无效：请填写真实 Base32 密钥，不要使用模板占位符（如 {secret}）';
  }
  return null;
}
