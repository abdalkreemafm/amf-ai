# NVD Correlation and Dashboard Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use the AMF1 project skill and test-driven-development workflow.

**Goal:** ربط نتائج NVD بالملاحظات المجمعة وعرضها في لوحة React كمطابقات احتمالية قابلة للمراجعة، مع قياس coverage والأداء.

**Architecture:** تبقى NVD طبقة معلوماتية منفصلة. يحول correlation كل Advisory إلى Observation مرتبطة بالأصل، مع provenance كامل وتصنيف `potential-match`، بينما يضيف API ملخص intel إلى Job/scan response وتستهلكه React في بطاقة مستقلة. لا يُرسل NVD أي payload ولا يرفع سجل CVE إلى إثبات استغلال.

**Tech Stack:** Python standard library، SQLite cache، unittest/coverage، React 19، TypeScript، Vitest، Testing Library، Vitest coverage-v8.

**Spec:** `docs/EXTERNAL_INTEL_INTEGRATION_PLAN_AR.md`

## Global Constraints

- الوضع الافتراضي دفاعي وقراءة فقط؛ لا exploit execution أو payloads.
- API محلي loopback، وNVD API key من `AMF_NVD_API_KEY` فقط.
- المطابقة `potential-match` أو `needs-review`، وليست `confirmed`.
- كل نتيجة خارجية تحتوي source/source_id/retrieved_at/source_url/license/confidence/raw_hash.
- عدم تسريب token في URL أو React state أو التقرير.

## Review Focus

- Advisory بلا CPE: يظهر بثقة منخفضة ولا يثبت التطابق.
- CVE مكرر من أكثر من module/provider: يُدمج دون فقد provenance.
- انقطاع NVD: تبقى نتائج cache ولا يفشل الفحص المحلي بالكامل.
- استجابة API قديمة أو ناقصة: تعرض الواجهة loading/error/empty states بوضوح.
- قوائم CVE كبيرة: pagination وقياس زمن correlation دون N+1 requests.

### Task 1: Correlation Intel Observations

**Files:** `amf/correlation.py`, `tests/test_amf.py` أو `tests/test_nvd.py`.

- [x] اكتب اختبارات فشل لتحويل Advisory إلى Observation مع `potential-match`, CPE، source وmatching_reason.
- [x] نفذ helper موحدًا يربط advisory بالأصل ويحافظ على provenance.
- [x] تحقق من deduplication وغياب CPE.

### Task 2: API Contract

**Files:** `amf/api.py`, `amf/jobs.py`, `src/services/api.ts`, `src/types/amf.ts`.

- [x] اكتب اختبارًا يثبت أن `/api/intel/nvd` يعيد intel summary.
- [x] أضف lookup معلوماتيًا منفصلًا لا يغيّر dry-run ولا يفشل scan المحلي.
- [x] حدّد أنواع TypeScript لـIntelObservation وNVDLookupResponse.

### Task 3: React Dashboard

**Files:** `src/App.tsx`, `src/App.test.tsx`, `src/styles.css`.

- [x] اختبر loading/error/match states وARIA.
- [x] أضف بطاقة NVD تعرض CVE، confidence، source، retrieved_at، وmatching_reason.
- [x] استخدم copy واضحًا: potential match / يحتاج مراجعة، مع رابط المصدر.

### Task 4: Coverage and Performance

**Files:** `package.json`, `package-lock.json`, `.github/workflows/ci.yml`, `docs/PERF.md`.

- [x] أضف `coverage` Python وVitest coverage-v8.
- [x] شغّل coverage مع أرقام موثقة بدل ادعاء 100%.
- [x] قس correlation وNVD normalization على fixture ثابتة، وسجّل median وعدد العناصر.
- [x] شغّل full verification ثم راجع diff والفرع.
