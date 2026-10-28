# AMF Defensive Security Framework Implementation Plan

**Goal:** بناء إطار Python دفاعي قابل للتوسعة يحاكي تنظيم Metasploit وتجربة أوامر CLI، مع فحوص غير استغلالية فقط.

**Architecture:** طبقة CLI تستدعي Registry للوحدات، وكل وحدة تنفذ عقدًا موحدًا وتعيد Findings منظمة. طبقة Safety تمنع التنفيذ الشبكي افتراضيًا وتسمح به فقط لهدف موجود في allowlist وبوجود `--execute`. طبقة Reporting تصدر JSON، مع إبقاء الاعتماديات ضمن مكتبة Python القياسية.

**Tech Stack:** Python 3.10+، `argparse`، `dataclasses`، `urllib`، `unittest`/`pytest` اختياريًا.

## القيود العامة

- لا payloads، ولا exploitation، ولا persistence، ولا credential theft، ولا shell execution.
- التنفيذ الشبكي معطل افتراضيًا.
- لا يُسمح إلا بأهداف صريحة في allowlist.
- الوحدة الأولى تفحص HTTP response headers فقط.
- كل عملية لها timeout وحد أقصى للبيانات وسجل قابل للتصدير.

## الملفات

- `amf/cli.py`: أوامر `list`, `info`, `use`, `check`, `report`, `doctor`.
- `amf/core.py`: أنواع النتائج وRegistry وتشغيل الوحدات.
- `amf/safety.py`: قراءة allowlist والتحقق من الهدف وسياسة التنفيذ.
- `amf/reporting.py`: تحويل النتائج إلى JSON.
- `amf/modules/base.py`: العقد الأساسي للوحدات.
- `amf/modules/http_headers.py`: فحص HTTP غير استغلالي لرؤوس الحماية.
- `tests/`: اختبارات Registry والسياسة والوحدة والتقرير.
- `README.md`: التثبيت والاستخدام والحدود الأمنية.
- `pyproject.toml`: metadata ونقطة التشغيل.

## خطوات التنفيذ

- [ ] إنشاء الحزمة والأنواع الأساسية وRegistry.
- [ ] إضافة Safety Policy مع allowlist و`--execute`.
- [ ] إضافة وحدة `scanner/http_headers` التي تستخدم HEAD أو GET محدودًا وتنتج ملاحظات فقط.
- [ ] إضافة CLI وتقارير JSON وأوامر الاستكشاف.
- [ ] إضافة README واختبارات.
- [ ] تشغيل compile والاختبارات وتجربة CLI في وضع dry-run.

## نقاط المراجعة

- الهدف غير الموجود في allowlist يجب أن يُرفض قبل أي اتصال.
- غياب `--execute` يجب أن ينتج dry-run ولا اتصالًا شبكيًا.
- الاستجابة التي لا تحتوي رؤوس حماية يجب أن تنتج Findings قابلة للإصلاح.
- الأخطاء والمهلات يجب أن تظهر كـ Findings أو أخطاء منظمة، لا traceback غير مفهوم.
- التقرير JSON يجب أن يكون قابلًا لإعادة التحميل ويحتوي metadata واضحة.
