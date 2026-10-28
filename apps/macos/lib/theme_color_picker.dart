import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app_ui.dart';

/// 自定义颜色仅在确认后返回，不提前写入偏好或修改全局主题。
Future<String?> showThemeColorPicker(BuildContext context, String initialColor) =>
    showDialog<String>(
      context: context,
      builder: (_) => _ThemeColorPicker(initialColor: initialColor),
    );

class _ThemeColorPicker extends StatefulWidget {
  const _ThemeColorPicker({required this.initialColor});
  final String initialColor;

  @override
  State<_ThemeColorPicker> createState() => _ThemeColorPickerState();
}

class _ThemeColorPickerState extends State<_ThemeColorPicker> {
  late HSVColor _hsv;
  late final TextEditingController _hex;
  bool _valid = true;

  String get _value => '#${(_hsv.toColor().toARGB32() & 0xFFFFFF)
      .toRadixString(16).padLeft(6, '0').toUpperCase()}';

  @override
  void initState() {
    super.initState();
    final hex = RegExp(r'^#[0-9a-fA-F]{6}$').hasMatch(widget.initialColor)
        ? widget.initialColor : AppPresentation.defaultAccentColor;
    _hsv = HSVColor.fromColor(Color(int.parse('FF${hex.substring(1)}', radix: 16)));
    _hex = TextEditingController(text: _value);
  }

  @override
  void dispose() {
    _hex.dispose();
    super.dispose();
  }

  void _select(HSVColor value) {
    setState(() {
      _hsv = value;
      _valid = true;
      _hex.text = _value;
    });
  }

  void _readHex(String text) {
    final hex = text.startsWith('#') ? text.substring(1) : text;
    setState(() {
      _valid = RegExp(r'^[0-9a-fA-F]{6}$').hasMatch(hex);
      if (_valid) {
        final next = HSVColor.fromColor(Color(int.parse('FF$hex', radix: 16)));
        // 灰阶没有色相，保留当前色相，便于重新增加饱和度。
        _hsv = next.saturation == 0 ? next.withHue(_hsv.hue) : next;
      }
    });
  }

  Widget _slider(String label, double value, double max, ValueChanged<double> onChanged,
          {bool hue = false}) =>
      Row(children: [
        SizedBox(width: 76, child: Text(label)),
        Expanded(child: Stack(alignment: Alignment.center, children: [
          if (hue) Positioned(left: 24, right: 24, height: 6,
            child: DecoratedBox(decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(6),
              gradient: const LinearGradient(colors: [
                Color(0xFFFF0000), Color(0xFFFFFF00), Color(0xFF00FF00),
                Color(0xFF00FFFF), Color(0xFF0000FF), Color(0xFFFF00FF), Color(0xFFFF0000),
              ]),
            )),
          ),
          Slider(
            value: value,
            max: max,
            activeColor: hue ? Colors.transparent : null,
            inactiveColor: hue ? Colors.transparent : null,
            thumbColor: hue ? HSVColor.fromAHSV(1, _hsv.hue, 1, 1).toColor() : null,
            label: value.round().toString(),
            semanticFormatterCallback: (value) => '$label ${value.round()}',
            onChanged: onChanged,
          ),
        ])),
      ]);

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const LText('theme.colors.customTitle'),
    content: SizedBox(
      width: 420,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            LayoutBuilder(builder: (context, constraints) {
              final width = constraints.maxWidth;
              const height = 200.0;
              void selectPosition(Offset position) => _select(_hsv
                  .withSaturation((position.dx / width).clamp(0.0, 1.0).toDouble())
                  .withValue((1 - position.dy / height).clamp(0.0, 1.0).toDouble()));
              return GestureDetector(
                onTapDown: (event) => selectPosition(event.localPosition),
                onPanStart: (event) => selectPosition(event.localPosition),
                onPanUpdate: (event) => selectPosition(event.localPosition),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(10),
                  child: SizedBox(height: height, child: Stack(fit: StackFit.expand, children: [
                    ColoredBox(color: HSVColor.fromAHSV(1, _hsv.hue, 1, 1).toColor()),
                    const DecoratedBox(decoration: BoxDecoration(gradient: LinearGradient(
                        colors: [Colors.white, Colors.transparent]))),
                    const DecoratedBox(decoration: BoxDecoration(gradient: LinearGradient(
                        begin: Alignment.topCenter, end: Alignment.bottomCenter,
                        colors: [Colors.transparent, Colors.black]))),
                    Positioned(
                      left: (_hsv.saturation * width - 8).clamp(0.0, width - 16).toDouble(),
                      top: ((1 - _hsv.value) * height - 8).clamp(0.0, height - 16).toDouble(),
                      child: Container(width: 16, height: 16,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          border: Border.all(color: Colors.white, width: 2),
                          boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 3)],
                        )),
                    ),
                  ])),
                ),
              );
            }),
            const SizedBox(height: 12),
            _slider(tr('theme.colors.hue'), _hsv.hue, 360,
                (value) => _select(_hsv.withHue(value)), hue: true),
            _slider(tr('theme.colors.saturation'), _hsv.saturation * 100, 100,
                (value) => _select(_hsv.withSaturation(value / 100))),
            _slider(tr('theme.colors.brightness'), _hsv.value * 100, 100,
                (value) => _select(_hsv.withValue(value / 100))),
            const SizedBox(height: 12),
            AppFieldRow(label: tr('theme.colors.hex'), child: TextField(
              controller: _hex,
              inputFormatters: [FilteringTextInputFormatter.allow(RegExp(r'[#0-9a-fA-F]'))],
              maxLength: 7,
              decoration: InputDecoration(
                hintText: '#565DD9', counterText: '',
                errorText: _valid ? null : tr('theme.colors.invalidHex'),
                prefixIcon: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Container(width: 20, height: 20,
                    decoration: BoxDecoration(color: _hsv.toColor(),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: Theme.of(context).dividerColor))),
                ),
              ),
              onChanged: _readHex,
            )),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(onPressed: () => Navigator.pop(context), child: const LText('common.cancel')),
      FilledButton(onPressed: _valid ? () => Navigator.pop(context, _value) : null,
          child: const LText('theme.colors.useColor')),
    ],
  );
}
