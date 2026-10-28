# AMF AI — Defensive Security Framework

إطار عمل دفاعي صغير وقابل للتوسعة لفحص الأنظمة المصرّح بها. يستعير من Metasploit فكرة الوحدات وواجهة CLI، لكنه لا ينفذ استغلالات أو حمولات أو جلسات تحكم.

## المزايا الحالية

- Registry للوحدات مع `list` و`info`.
- وحدة `scanner/http_headers` لفحص رؤوس HTTP الأمنية فقط.
- وحدات فعلية لاستكشاف Cookies والتحويلات وTLS والشهادة وDNS الأساسي.
- وحدات تحليل متقدمة تكشف تسرب أخطاء قواعد البيانات، مؤشرات أسطح XSS، وأخطاء تهيئة الخادم دون حقن أو Payloads.
- وضع `dry-run` افتراضيًا؛ لا يحدث اتصال شبكي ما لم تستخدم `--execute`.
- allowlist إلزامية للهدف قبل السماح بأي اتصال.
- تقارير JSON.
- تقرير منظم لكل اكتشاف يتضمن النوع والخطورة والثقة والدليل والأثر والإصلاح بالعربية والإنجليزية.
- تصدير JSON وMarkdown وHTML عبر `--format` و`--language`.
- مكتبة Python القياسية فقط.
- فهرس Modules ببيانات وصفية وبحث حسب الاسم والوصف والوسوم.
- Profiles جاهزة: `quick` و`web` و`discovery` و`full`.
- فحص CORS والملفات الحساسة وSPF/DMARC.
- إخراج SARIF وخيار `--fail-on` للتكامل مع CI/CD.

## التثبيت

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## الاستخدام

```bash
amf list
amf search headers
amf profiles
amf info scanner/http_headers
amf doctor

# dry-run: لا يوجد اتصال شبكي
amf check scanner/http_headers https://lab.local --allow https://lab.local

# تنفيذ فحص HEAD محدود على هدف مصرّح به صراحة
amf check scanner/http_headers https://lab.local \
  --allow https://lab.local --execute --timeout 5 \
  --report report.json --format json --language both
```

مثال تقرير Markdown أو HTML:

```bash
amf check scanner/http_cookies https://lab.local \
  --allow https://lab.local --execute \
  --report report.md --format markdown --language both

amf check scanner/http_headers https://lab.local \
  --allow https://lab.local --execute \
  --report report.html --format html --language both
```

كل finding في التقرير يحتوي على `type` و`severity` و`confidence` و`evidence`، بالإضافة إلى العنوان والوصف والإصلاح بالعربية والإنجليزية.

يمكن تشغيل Profile محدد بدل جميع الوحدات:

```bash
amf full https://lab.local --allow https://lab.local \
  --profile web --execute --format html --language both --report web.html
```

تقرير SARIF وحاجز CI:

```bash
amf full https://lab.local --allow https://lab.local \
  --profile web --execute --format sarif --report results.sarif --fail-on high
```

استفدنا من الأفكار المعمارية العامة في Metasploit، مثل Registry والفهرسة وmetadata وProfiles وواجهة `list/info/search/use`. لم تُنسخ وحدات أو Payloads أو موارد تنفيذ هجومية من Metasploit إلى هذا المشروع. يعتمد AMF على تنفيذ أصلي مستقل، وتجب مراجعة ترخيص أي مكوّن خارجي قبل استخدامه.

تظهر الملفات الحساسة في التقرير من حيث النوع والمسار والحجم والدليل التشخيصي، لكن محتوى المفاتيح وكلمات المرور والرموز السرية يُحجب دائمًا ولا يُكتب خامًا في التقرير أو السجل.

## التشغيل على Termux

لا يحتاج الإصدار الحالي إلى `nmap` أو `hydra` أو حزم خارجية. بعد تثبيت Python في Termux، شغّل الواجهة التفاعلية:

```bash
pkg update
pkg install python
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m amf
```

## لوحة React المحلية

شغّل محرك API في نافذة طرفية:

```bash
python -m amf api
```

ثم شغّل واجهة التطوير في نافذة أخرى:

```bash
npm install
npm run dev
```

افتح `http://127.0.0.1:5173`. تستدعي الواجهة API محليًا فقط، ويبقى التحقق من `allowlist` و`dry-run` داخل Python وليس داخل المتصفح.

داخل الواجهة:

```text
amf > list
amf > search headers
amf > list
amf > search headers
amf > profiles
amf > use scanner/http_headers
amf (scanner/http_headers) > set TARGET http://127.0.0.1:8000
amf (scanner/http_headers) > set ALLOW http://127.0.0.1:8000
amf (scanner/http_headers) > check
amf (scanner/http_headers) > set EXECUTE true
amf (scanner/http_headers) > run
amf (scanner/http_headers) > report report.json
amf (scanner/http_headers) > exit
```

`check` لا يتصل بالشبكة. الأمر `run` يبقى محميًا ولا يعمل إلا بعد ضبط `EXECUTE true` ووجود الهدف نفسه في `ALLOW`.

استخدم الأداة فقط على أنظمة تملكها أو لديك تفويض مكتوب لاختبارها. لا توجد في المشروع وظائف لتوليد payloads أو تنفيذ أوامر على أهداف أو فتح جلسات أو تجاوز ضوابط.

## الوحدات الحالية

```text
scanner/http_headers       HTTP security headers
scanner/http_cookies       Secure, HttpOnly and SameSite
scanner/http_redirects     HTTP to HTTPS redirect posture
scanner/tls_certificate    TLS negotiation and certificate expiry
scanner/dns_basic          IPv4/IPv6 resolution discovery
scanner/dns_email_security SPF and DMARC posture
scanner/http_cors          CORS configuration review
scanner/http_sql_errors    Passive database error disclosure
scanner/http_xss_surface   Passive XSS surface indicators
scanner/sensitive_files    Sensitive file exposure review
scanner/server_misconfiguration  Passive server configuration checks
```

كل وحدة تنفذ فحصًا محدودًا غير تدخلي. وحدتا SQL وXSS لا تحقنان مدخلات ولا ترسلان Payloads؛ لذلك تسجلان «مؤشرًا يحتاج مراجعة» عندما لا يكفي الدليل لإثبات قابلية الاستغلال. كل Finding يحتوي النوع والخطورة والثقة والدليل والإصلاح بالعربية والإنجليزية.

## إضافة وحدة

أنشئ صنفًا يرث `Module` ويعرّف `name` و`description` و`run`، ثم سجّله باستخدام `@register` وأضفه إلى `amf/modules/__init__.py`. يجب أن تكون الوحدة غير استغلالية، محدودة المعدل، ولا تغيّر حالة الهدف.

## الاختبارات

```bash
python -m unittest discover -s tests -v
python -m compileall -q amf
```
