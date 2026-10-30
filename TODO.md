# AMF Dashboard TODO

- [x] API محلي على 127.0.0.1:8765 مع `/api/health`, `/api/modules`, `/api/profiles`, `/api/scan`.
- [x] إبقاء dry-run افتراضيًا والتحقق من allowlist داخل Python.
- [x] لوحة React تعرض الوحدات والـ Profiles وإحصاءات Findings.
- [x] عرض الدليل والأثر والإصلاح والثقة لكل Finding.
- [x] منع عرض الأسرار الخام أو تخزينها في المتصفح.
- [x] Jobs غير متزامنة مع polling والتقدم والإلغاء.
- [x] نماذج Asset وObservation وCorrelation لإزالة تكرار الأدلة.
- [x] Endpoint `/api/jobs/<id>/events` وملخص correlation داخل Job.
- [x] نجاح `python3 -m unittest discover -s tests -v`.
- [x] نجاح `npm run build`.

## المرحلة التالية

- [ ] إضافة سجل تاريخي اختياري للفحوص ومقارنة تقريرين.
- [ ] ربط CPE/CVE/CVSS كمطابقة احتمالية تحتاج مراجعة.
- [ ] إضافة adapters لمصادر CT وDNS إضافية مع حدود أصول واضحة.
