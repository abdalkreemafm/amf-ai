# خطة تكامل مصادر الاستخبارات الأمنية الخارجية في AMF AI

## القرار المعماري

يجب فصل مصادر الاستخبارات عن محرك الفحص. المصدر الخارجي لا يشغّل هدفًا ولا يرسل Payload؛ وظيفته إثراء `Observation` و`Finding` بعد أن ينتج AMF أصلًا أو نسخة منتج وإصدارًا. كل سجل يجب أن يحتفظ بـ `source`, `source_id`, `retrieved_at`, `source_url`, `license`, `confidence` و`raw_hash`، مع تخزين نسخة منقحة أو معرفًا بدل نسخ محتوى حساس أو كود استغلال.

البنية المقترحة:

```text
amf/intel/
├── base.py              # IntelProvider ونتيجة موحدة
├── models.py            # Advisory, ProductMatch, IntelEvidence
├── cache.py             # SQLite أو JSONL مع TTL وETag
├── normalizer.py        # CVE/CPE/CVSS وحقول المصدر
├── nvd_provider.py      # NVD API 2.0 أو feeds
├── exploitdb_provider.py# metadata/reference-only
└── policy.py            # المعدل والترخيص ومنع تنزيل exploit code
```

## NVD

تكون NVD المصدر الأول للمطابقة المنظمة. استخدم CVE/CPE APIs 2.0 للمطابقات الدقيقة أو للمزامنة التزايدية، واستخدم JSON 2.0 feeds عند إنشاء مرآة محلية. توصي NVD بأن تبدأ المزامنة بصفحات `startIndex` و`resultsPerPage`، ثم تستخدم نوافذ `lastModStartDate` و`lastModEndDate` للتحديث بدل إعادة تنزيل كل البيانات. كما توصي بالانتظار عدة ثوانٍ بين الطلبات؛ الحد العام المذكور هو 5 طلبات خلال 30 ثانية، ويرتفع إلى 50 مع API key. [1]

يجب بناء `NVDProvider` بحيث يملك طابورًا واحدًا للطلبات، وbackoff عند 429/503، وcache، وETag/Last-Modified إن توفر، ونافذة تحديث لا تتكرر أكثر من اللازم. لا يضع المفتاح في React أو التقارير؛ يُقرأ من `AMF_NVD_API_KEY` أو من مخزن أسرار خارجي.

للمزامنة المحلية، افحص ملف `.meta` قبل تنزيل feed؛ ملف meta يحتوي على وقت التعديل والحجم وSHA-256، وfeeds `recent` و`modified` تُحدّث تقريبًا كل ساعتين وفق صفحة NVD. افحص SHA-256 ثم استورد إلى SQLite داخل معاملة واحدة، مع الاحتفاظ بآخر cursor حتى يمكن استئناف العمل بعد انقطاع. [2]

يجب أن يكتب AMF في واجهته إشعار NVD المطلوب: `This product uses data from the NVD API but is not endorsed or certified by the NVD.` ولا يجوز صياغة التقرير كأنه اعتماد أو تصديق من NVD. [1]

## Exploit-DB

ينبغي التعامل مع Exploit-DB كمصدر مراجع وmetadata، لا كمصدر لتنزيل أو تشغيل exploit code. ابدأ بمزامنة فهرس metadata فقط مثل رقم الإدخال، العنوان، النوع، المنصة، التاريخ، المراجع وCVE إن وجد. خزّن رابط المصدر وhash للبيانات المستوردة، ولا تُضمّن نصوص الاستغلال أو ملفات shellcode في تقارير AMF الافتراضية.

لا تعتمد على scraping واسع للموقع. شروط Exploit-DB تنص على منع الطلبات المتكررة أو التي تضع عبئًا غير مناسب، وتذكر أن إساءة استخدام API أو كثرة الطلبات قد تؤدي إلى تعليق الوصول، كما تمنع مشاركة API tokens لتجاوز حدود المعدل. استخدم API رسميًا إن كان متاحًا لحساب المستخدم، مع rate limiter وحفظ token خارج المستودع. [3]

لا تفترض أن وجود سجل في Exploit-DB يثبت قابلية الاستغلال. يصنف AMF النتيجة مثلًا إلى `reference-only` أو `needs-review`، ويربطها بـ CVE/CPE وملاحظة الإصدار، دون رفعها تلقائيًا إلى `confirmed`.

## المطابقة وCorrelation

المسار المقترح هو:

```text
Service observation
  → product/version extraction
  → CPE candidates
  → NVD CVE matches
  → Exploit-DB reference enrichment
  → confidence scoring
  → Finding يحتاج مراجعة
```

تكون الثقة `high` فقط عند وجود CPE واضح وإصدار مؤكد ومصدر موثوق. أما match مبني على banner ناقص أو اسم منتج غامض فيبقى `low` أو `medium`. يجب حفظ سبب المطابقة في `matching_reason` حتى يستطيع المستخدم مراجعة القرار.

## مراحل التنفيذ

1. إضافة نماذج `Advisory`, `ProductMatch` و`IntelEvidence` إلى طبقة النماذج الحالية.
2. إنشاء cache SQLite مع جداول `sources`, `advisories`, `cpe_matches`, `sync_state`.
3. تنفيذ NVD provider للبحث عن CVE محدد ثم CPE ثم المزامنة التزايدية.
4. إضافة اختبارات fixtures محلية لا تتصل بالشبكة، واختبار 429 والمهلة والاستئناف وchecksum.
5. إضافة Exploit-DB metadata provider بحدود معدل صريحة ودون تنزيل كود الاستغلال.
6. دمج النتائج مع `correlation.py` وإظهار المصدر والرابط ووقت الجلب في التقرير.
7. إضافة سياسة freshness: تحذير إذا تجاوزت البيانات عمرًا محددًا، وعدم تقديم نتيجة قديمة كحقيقة حديثة.
8. إضافة provenance و`THIRD_PARTY_NOTICES.md` لكل مصدر وترخيص.
9. عرض المطابقة في React كـ `potential match` أو `reference-only` بدل "ثغرة مؤكدة".
10. إبقاء أي check أو exploit execution خارج هذا المسار وبموافقة مستقلة؛ هذه الطبقة معلوماتية فقط.

## معايير قبول مهمة

يجب أن يرفض النظام تنزيل بيانات ضخمة من Exploit-DB دون تفعيل صريح للـ provider، وأن يرفض مشاركة المفاتيح في السجل، وأن يعمل بالكامل من cache عند انقطاع الشبكة، وأن يميز بين `published_at` و`modified_at`، وأن يعرض دائمًا المصدر ووقت الجلب ودرجة الثقة.

## References

[1]: https://nvd.nist.gov/developers/start-here "NVD API Getting Started and Rate Limits"
[2]: https://nvd.nist.gov/vuln/data-feeds "NVD Data Feeds and Synchronization"
[3]: https://www.exploit-db.com/terms "Exploit Database Terms of Service and API Terms"
