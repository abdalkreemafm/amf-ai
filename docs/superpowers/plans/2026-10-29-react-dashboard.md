# AMF React Dashboard Implementation Plan

**Goal:** إضافة لوحة React تفاعلية مرتبطة بمحرك AMF Python عبر API محلي آمن.

**Architecture:** يبقى Python مصدر الحقيقة لتنفيذ الوحدات والتحقق من allowlist والتقارير. تقدم React العرض والإدخال فقط عبر `127.0.0.1:8765` أثناء التطوير، مع dry-run افتراضيًا.

**Tech Stack:** Python standard library HTTP server، React 19، TypeScript، Vite.

## القرارات التصميمية

- نمط لوحة عمليات أمنية داكنة، كثافة معلومات مرتفعة، ألوان الخطورة محدودة وواضحة.
- كل Finding يعرض النوع والخطورة والثقة والدليل والأثر والإصلاح.
- الأدلة الحساسة تبقى منقحة؛ الواجهة لا تستلم كلمات مرور أو Tokens خام.
- لا يتم تخفيف allowlist أو dry-run؛ قوة التقرير تأتي من أدلة آمنة قابلة للتحقق.

## الملفات

- `amf/api.py`: API محلي لمسارات health/modules/profiles/scan.
- `amf/cli.py`: أمر تشغيل API.
- `src/main.tsx`: نقطة دخول React.
- `src/App.tsx`: لوحة الفحص والنتائج.
- `src/styles.css`: تصميم اللوحة.
- `src/services/api.ts`: عميل API typed.
- `src/types/amf.ts`: نماذج النتائج والوحدات.
- `package.json`, `vite.config.ts`, `tsconfig.json`, `index.html`: إعداد Vite.
- `tests/test_amf.py`: اختبارات API والتنقيح والتشغيل dry-run.

## التنفيذ

- [ ] إضافة API محلي مع allowlist وprofile وdry-run.
- [ ] إضافة تطبيق React وعميل API ونماذج النتائج.
- [ ] إضافة تصميم لوحة النتائج والتفاصيل.
- [ ] إضافة اختبارات Python وبناء Vite.
- [ ] توثيق التشغيل على Termux.
