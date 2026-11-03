# AMF AI Performance and Coverage Baseline

هذا المستند يسجل خط أساس قابلًا لإعادة الإنتاج بعد ربط NVD بمحرك correlation ولوحة React. القياسات محلية على fixture ثابتة ولا تعتمد على شبكة NVD أو هدف خارجي.

## Coverage

شُغّلت تغطية Python بالأمر التالي:

```bash
coverage erase
coverage run --branch -m unittest discover -s tests -v
coverage report -m
```

آخر نتيجة موثقة: **46 اختبارًا ناجحًا**، وتغطية كلية **71%** بحسب عمود Coverage.py المركب. طبقة NVD بلغت **80%**، و`amf/correlation.py` بلغت **98%**. الرقم الكلي يتأثر بوحدات CLI وadapters التي لا تُستدعى في كل اختبار، لذلك لا يُستخدم كادعاء أن كل المسارات الإنتاجية مغطاة بالتساوي.

تُشغّل تغطية React بالأمر:

```bash
npm run test:coverage
```

آخر نتيجة: **4 اختبارات ناجحة**، **82.92% statements**، **67.53% branches**، **77.77% functions**، و**85.5% lines** في `App.tsx`.

## Performance

يُعاد تشغيل benchmark الخاص بطبقة المعلومات بالأمر:

```bash
python scripts/benchmark_intel.py
```

على 5 تكرارات وfixture من 1,000 Advisory و500 سجل NVD، كان الوسيط المقاس:

| العملية | حجم fixture | الوسيط |
|---|---:|---:|
| `correlate_intel` | 1,000 Advisory | 2.00 ms |
| NVD normalization | 500 vulnerability records | 1.33 ms |

قياس بناء الواجهة:

```bash
TIMEFORMAT='frontend_build_wall_seconds %R'; time npm run build
```

استغرق البناء الأخير **1.829 ثانية**، وكان حجم JavaScript الخام **236,526 bytes** وحجم gzip المعلن من Vite **73.75 kB**، بينما بلغ CSS الخام **9,751 bytes** وgzip **2.85 kB**. هذه قياسات baseline وليست بديلًا عن Lighthouse أو RUM في بيئة المستخدم.

لا توجد في هذه المرحلة عتبة فشل آلية للـcoverage الكلي؛ تُستخدم الأرقام لاكتشاف الانحدار، مع إبقاء اختبارات NVD وcorrelation والواجهة الجديدة ضمن بوابة CI.
