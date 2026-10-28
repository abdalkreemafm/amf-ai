# Termux Console Extension Plan

**Goal:** إضافة واجهة طرفية تفاعلية تعمل على Termux بمكتبة Python القياسية وتستدعي نفس محرك الوحدات الآمن المستخدم في CLI.

**Architecture:** `amf/__main__.py` يتيح التشغيل بـ `python -m amf`. عند عدم وجود أمر، تُفتح Console صغيرة في `amf/console.py`. تحفظ الجلسة الوحدة والهدف والخيارات في الذاكرة، وتمنع `run` من الاتصال ما لم توجد allowlist ويُفعّل التنفيذ صراحة.

## القيود

- لا تثبيت تلقائي لحزم Termux ولا أوامر shell من مدخلات المستخدم.
- الأوامر المدعومة: `help`, `list`, `info`, `use`, `options`, `set`, `check`, `run`, `report`, `clear`, `exit`.
- `check` يعاين الإعدادات و`run` ينفذ فقط عند `EXECUTE=true` ووجود هدف في allowlist.
- تعتمد الواجهة على `cmd.Cmd` وPython standard library.

## التغييرات

- [ ] إنشاء `amf/console.py` مع parser للأوامر وحالة جلسة.
- [ ] إنشاء `amf/__main__.py` لتشغيل CLI من Termux.
- [ ] تحديث CLI بإضافة `console` وقراءة متغيرات البيئة الاختيارية.
- [ ] تحديث README بأوامر Termux.
- [ ] إضافة اختبارات للأوامر dry-run ورفض التنفيذ غير المسموح.
- [ ] تشغيل الاختبارات و`compileall` وتجربة console غير التفاعلية.
