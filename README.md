## Attribution

This project is a derivative work based on the open-source CumulusVPN project  
(MIT License). See the `LICENSE` and `NOTICE` files for details.

# Fluxcore CLI

کلاینت خط فرمان Fluxcore برای لینوکس، macOS و ویندوز. این برنامه یک **پروکسی محلی** روی `127.0.0.1` بالا می‌آورد و ترافیک برنامه‌هایی که به آن وصل می‌شوند را از فلیت CumulusVPN عبور می‌دهد.

- **بدون TUN، بدون root و بدون تغییر روت سیستم.** هیچ ترافیکی به‌صورت خودکار از تونل رد نمی‌شود؛ خودتان برنامه را به پروکسی وصل می‌کنید.
- پروتکل‌ها: `wg` (WireGuard)، `awg` (AmneziaWG با obfuscation) و `wg-tls` (WireGuard داخل TLS).
- **فقط پلن رایگان.** هیچ دستور پرداخت، ارتقا یا بررسی اشتراکی وجود ندارد.
- پشتیبانی از SOCKS5 و HTTP روی دو پورت مستقل، split tunneling، مولتی‌هاپ، kill switch و اتصال مجدد خودکار.
- **آپ‌استریم:** همهٔ اتصال‌های خود کلاینت (کشف، enroll، تونل و مسیرهای مستقیم) می‌توانند از یک پروکسی SOCKS5 یا HTTP بالادستی رد شوند؛ برای وقتی که دسترسی مستقیم به فلیت فیلتر است.

---

## دانلود

باینری‌های آمادهٔ لینوکس و ویندوز (amd64) در [Releases](https://github.com/FossilizedProgrammer/fluxcore/releases) قرار می‌گیرند. این فایل‌ها را GitHub Actions از سورس می‌سازد و مستقیماً به Release اضافه می‌کند.

---

## پیش‌نیاز

- Go نسخه ۱.۲۵ یا بالاتر (پروژه با Go 1.27 تست شده است).
- دسترسی خروجی UDP (برای `wg`/`awg`) و TCP (برای `wg-tls`).

## ساخت

```bash
git clone https://github.com/FossilizedProgrammer/fluxcore.git
cd fluxcore
go build -o fluxcore .
```

برای نصب در مسیر سیستم:

```bash
sudo install -m 0755 fluxcore /usr/local/bin/fluxcore
```

اجرای بدون ساخت هم ممکن است:

```bash
go run . --help
```

---

## شروع سریع

```bash
# ۱) کشورهای موجود را ببینید (بدون پینگ سریع‌تر است)
./fluxcore list --no-latency

# ۲) پروکسی را روی یک کشور مشخص بالا بیاورید
./fluxcore run --country DE

# ۳) در ترمینال دیگر بررسی کنید
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

اگر `--country` را ندهید، سریع‌ترین گیت‌وی انتخاب می‌شود:

```bash
./fluxcore
```

`run` دستور پیش‌فرض است، بنابراین `./fluxcore --country DE` هم همان کار را می‌کند.

برای توقف: `Ctrl+C`.

---

## وصل کردن برنامه‌ها به پروکسی

پیش‌فرض: SOCKS5 روی `127.0.0.1:1080` و HTTP روی `127.0.0.1:1081`. هر دو پورت مستقل‌اند.

**curl**

```bash
# SOCKS5 (DNS هم از تونل حل می‌شود)
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me

# HTTP proxy
curl -x http://127.0.0.1:1081 https://ifconfig.me
```

**مرورگر / سیستم**

- SOCKS5: هاست `127.0.0.1`، پورت `1080`، نوع SOCKS v5. اگر گزینه «Proxy DNS when using SOCKS v5» وجود دارد، فعال کنید.
- HTTP: هاست `127.0.0.1`، پورت `1081`.

**برنامه‌های دیگر** از متغیرهای محیطی استاندارد استفاده می‌کنند:

```bash
export ALL_PROXY=socks5h://127.0.0.1:1080
```

پورت‌های دیگری بخواهید:

```bash
./fluxcore run --listen 127.0.0.1:9050 --http-listen 127.0.0.1:9051
```

فقط آدرس‌های loopback پذیرفته می‌شوند؛ `0.0.0.0` یا IP شبکه رد می‌شود تا پروکسی به‌طور ناخواسته روی شبکه باز نشود.

---

## دستورها

| دستور | کار |
|---|---|
| `fluxcore [run] [flags]` | بالا آوردن پروکسی (دستور پیش‌فرض) |
| `fluxcore list [--locations] [--json] [--no-latency]` | فهرست کشورها یا شهرها با پینگ و بار |
| `fluxcore status` | وضعیت نشست در حال اجرا |
| `fluxcore config [get KEY \| set KEY VALUE \| path]` | مشاهده/تغییر تنظیمات ذخیره‌شده |
| `fluxcore identity [show \| recovery \| import KEY]` | کلید عمومی، کلید بازیابی، بازیابی هویت |
| `fluxcore dns [list \| set ID]` | انتخاب resolver داخل تونل |
| `fluxcore split [...]` | قواعد split tunneling |
| `fluxcore favorites [list \| add LOC \| remove LOC \| clear]` | لوکیشن‌های موردعلاقه |
| `fluxcore version` | نسخه و پلتفرم |

### گزینه‌های `run`

| گزینه | توضیح |
|---|---|
| `-c, --country CODE[:CITY]` | انتخاب کشور یا شهر (مثلاً `de` یا `us:new york`) |
| `--entry CODE[:CITY]` | هوپ ورودی مولتی‌هاپ (خودش `--multihop` را فعال می‌کند) |
| `--exit CODE[:CITY]` | هوپ خروجی مولتی‌هاپ |
| `--multihop` | تونل تودرتو: entry فقط exit را می‌بیند، exit فقط مقصد را |
| `--stealth` | ترجیح ترنسپورت مقاوم به DPI (`wg-tls` سپس `awg`) |
| `--speed` | ترجیح WireGuard ساده |
| `--auto` | انتخاب خودکار ترنسپورت (پیش‌فرض) |
| `--upstream URL` | عبور کل ترافیک از پروکسی بالادستی: `socks5://user:pass@HOST:PORT` یا `http://HOST:PORT` |
| `--no-upstream` | نادیده گرفتن آپ‌استریم ذخیره‌شده برای همین اجرا |
| `-l, --listen ADDR` | آدرس SOCKS5 (فقط loopback، پیش‌فرض `127.0.0.1:1080`) |
| `--http-listen ADDR` | آدرس HTTP (فقط loopback، پیش‌فرض `127.0.0.1:1081`) |
| `--no-kill-switch` | در قطع تونل، درخواست‌ها مستقیم بروند (پیش‌فرض: رد شوند) |
| `--no-reconnect` | هنگام قطع/شکست اتصال خارج شو (پیش‌فرض: تلاش مجدد) |
| `-v, --verbose` | لاگ جزئیات پروکسی و WireGuard |

مثال‌ها:

```bash
# سریع‌ترین گیت‌وی
./fluxcore

# آلمان، حالت مقاوم به DPI
./fluxcore run --country DE --stealth

# دو هوپ: ورود لهستان، خروج آلمان
./fluxcore run --entry PL --exit DE

# پورت‌ها و لاگ دلخواه
./fluxcore run --country NL --listen 127.0.0.1:8080 --http-listen 127.0.0.1:8081 -v
```

### `list`

```bash
./fluxcore list                 # کشورها + اندازه‌گیری پینگ
./fluxcore list --no-latency    # سریع، بدون پینگ
./fluxcore list --locations     # شهرها (برای انتخاب CODE:CITY)
./fluxcore list --json          # خروجی JSON
```

انتخاب شهر:

```bash
./fluxcore run --country "us:new york"
```

### `status`

```bash
./fluxcore status
```

اگر پروسه مرده باشد، فایل وضعیت کهنه تشخیص داده و پاک می‌شود.

### `config`

```bash
./fluxcore config
./fluxcore config get country
./fluxcore config set country DE
./fluxcore config set transport stealth
./fluxcore config set listen 127.0.0.1:9050
./fluxcore config path
```

کلیدهای قابل تنظیم:

| کلید | مقادیر |
|---|---|
| `country` | کد کشور، `CODE:CITY` یا `auto` |
| `route` | `single` یا `multihop` |
| `transport` | `auto`، `stealth` یا `speed` |
| `entry` / `exit` | لوکیشن هوپ‌ها |
| `listen` | آدرس loopback با پورت |
| `dns` | شناسه یکی از resolverها (`cloudflare`, `google`, `quad9`, `dns4eu`, `adguard`, `family`) |
| `kill-switch` | `on`/`off` |
| `reconnect` | `on`/`off` |
| `diversity` | `on`/`off` (در مولتی‌هاپ کشور entry و exit متفاوت باشد) |
| `identity-backup` | `on`/`off` |
| `upstream` | آدرس پروکسی بالادستی، یا `off` برای غیرفعال کردن |

### `identity`

هویت یک جفت‌کلید WireGuard است و همان چیزی است که گیت‌وی شما را می‌شناسد.

```bash
./fluxcore identity show
./fluxcore identity recovery     # کلید بازیابی CVPN-...
./fluxcore identity import CVPN-...
```

- با اولین اجرا، کلید ساخته می‌شود.
- کلید بازیابی را جای امن نگه دارید؛ هر کسی آن را داشته باشد می‌تواند به‌جای شما وصل شود.
- `import` هویت فعلی را با کلید داده‌شده جایگزین می‌کند.
- بکاپ به‌صورت پیش‌فرض در کنار کانفیگ با مجوز `0600` ذخیره می‌شود.

### `dns`

```bash
./fluxcore dns list
./fluxcore dns set quad9
```

`cloudflare` یعنی از resolver خود گیت‌وی استفاده شود؛ بقیه مستقیماً داخل تونل صدا زده می‌شوند. کوئری‌های DNS مربوط به مسیرهای تونل از داخل تونل انجام می‌شوند تا نشت نکنند.

### `split`

split tunneling روی خود کلاینت ارزیابی می‌شود و گیت‌وی از قواعد خبر ندارد.

```bash
./fluxcore split show
./fluxcore split mode include        # فقط قواعد matched از تونل بروند
./fluxcore split mode exclude        # قواعد matched مستقیم بروند
./fluxcore split add domain example.com
./fluxcore split add domain "*.example.com"
./fluxcore split add cidr 192.168.1.0/24
./fluxcore split remove 1            # با شماره
./fluxcore split remove example.com  # یا با مقدار
./fluxcore split lan on              # شبکه محلی همیشه مستقیم
./fluxcore split dns system          # DNS مقصدهای مستقیم از سیستم
./fluxcore split clear
```

- `include`: فقط ترافیک منطبق با قواعد وارد تونل می‌شود.
- `exclude`: ترافیک منطبق مستقیم می‌رود و بقیه از تونل.
- `split dns tunnel|system` تعیین می‌کند نام دامنه‌های مسیر مستقیم با DNS تونل حل شود یا با resolver سیستم.
- افزودن اولین قاعده وقتی mode روی `off` است، آن را به `include` تغییر می‌دهد.
- تغییرات هنگام اجرای پروکسی اعمال نمی‌شوند؛ یک‌بار پروکسی را restart کنید.

### `favorites`

```bash
./fluxcore favorites add DE
./fluxcore favorites add "us:new york"
./fluxcore favorites list
./fluxcore favorites remove DE
./fluxcore favorites clear
```

اگر هیچ کشوری انتخاب نکرده باشید، لوکیشن‌های موردعلاقه در مسیر تک‌هاپ اولویت پیدا می‌کنند. با انتخاب صریح `--country` یا `config set country`، اولویت به همان انتخاب می‌رسد.

---

## رفتار شبکه

### حالت‌های ترنسپورت

| حالت | ترتیب ترجیح |
|---|---|
| `auto` (پیش‌فرض) | `wg`، `awg`، `wg-tls` |
| `speed` | `wg`، `awg` |
| `stealth` | `wg-tls`، `awg` |

اگر یک ترنسپورت شکست بخورد، ترنسپورت بعدی همان زنجیره امتحان می‌شود. در حالت `stealth` اگر گیت‌وی هیچ ترنسپورت مقاوم به DPI نداشته باشد، خطا می‌دهد و به `wg` ساده سقوط نمی‌کند.

### مولتی‌هاپ

```bash
./fluxcore run --entry PL --exit DE
```

- هوپ ورودی فقط آدرس هوپ خروجی را می‌بیند و هوپ خروجی فقط مقصد نهایی را؛ هیچ‌کدام هر دو طرف را نمی‌بینند.
- هوپ ورودی نمی‌تواند `wg-tls` باشد؛ در این حالت پیام خطا داده می‌شود و ترنسپورت دیگری امتحان می‌شود.
- با `config set diversity on` می‌توان الزام کرد کشور entry و exit متفاوت باشد.

### آپ‌استریم (عبور از فیلترینگ)

اگر دسترسی مستقیم به گیتوی‌ها فیلتر است، کلاینت را از یک پروکسی بالادستی (مثلاً xray/v2ray/nekoray روی لوکال) عبور دهید:

```bash
./fluxcore run --upstream socks5://127.0.0.1:10808
./fluxcore run --upstream http://127.0.0.1:8080 --stealth

# دائمی:
./fluxcore config set upstream socks5://127.0.0.1:10808
./fluxcore config set upstream off
```

- آپ‌استریم روی **همهٔ** اتصال‌های خود کلاینت اعمال می‌شود: کشف فلیت، `/v1/info`، enroll، خود تونل و مقصدهای split که «مستقیم» هستند. نام‌کاربری/رمز در URL پشتیبانی می‌شود.
- **SOCKS5:** هم `CONNECT` (TCP) و هم `UDP ASSOCIATE`، بنابراین `wg`، `awg`، `wg-tls` و مولتی‌هاپ همه کار می‌کنند. پروکسی بالادستی باید UDP را قبول کند (xray/sing-box معمولاً با `udp: true`).
- **HTTP/HTTPS:** فقط `CONNECT` (TCP)، پس `wg-tls` کار می‌کند؛ `wg`/`awg` خطا می‌دهند و در حالت `auto` خودکار به `wg-tls` سقوط می‌کنند. برای اطمینان از `--stealth` استفاده کنید.
- با آپ‌استریم HTTP، مولتی‌هاپ ممکن نیست (هوپ ورودی UDP است) و با SOCKS5 ممکن است.
- بدون `--upstream` (یا با `off`) رفتار قبلی است: اتصال مستقیم از سیستم.
- `list` هم از آپ‌استریم ذخیره‌شده استفاده می‌کند.

### Kill switch و اتصال مجدد

- پیش‌فرض: اگر تونل قطع شود، درخواست‌هایی که باید از تونل بروند **رد می‌شوند** (fail-closed).
- `--no-kill-switch`: در همین شرایط مستقیم و بدون تونل ارسال می‌شوند.
- به‌طور پیش‌فرض کلاینت با backoff دوباره وصل می‌شود؛ listener پروکسی بالا می‌ماند. `--no-reconnect` در عوض برنامه را خارج می‌کند.
- مسیرهای split که مستقیم هستند در قطعی تونل هم مستقیم می‌مانند.

### محدودیت‌های پروکسی

- SOCKS5 فقط `CONNECT` را پشتیبانی می‌کند؛ `UDP ASSOCIATE` رد می‌شود.
- HTTP به شکل `CONNECT` و absolute-form پشتیبانی می‌شود.
- چون UDP از پروکسی عبور نمی‌کند، برنامه‌هایی که فقط QUIC/UDP دارند ممکن است به TCP سقوط کنند یا کار نکنند.
- هیچ TUN یا روت سیستمی ساخته نمی‌شود؛ برنامه‌هایی که از تنظیمات پروکسی پیروی نمی‌کنند از تونل عبور نمی‌کنند.

---

## فایل‌ها و مسیرها

تنظیمات در پوشه کانفیگ کاربر ذخیره می‌شوند (خروجی `config path`):

| سیستم | مسیر معمول |
|---|---|
| لینوکس | `~/.config/fluxcore/` |
| macOS | `~/Library/Application Support/fluxcore/` |
| ویندوز | `%AppData%\fluxcore\` |

فایل‌ها:

- `config.json` — تنظیمات و جفت‌کلید (مجوز `0600`)
- `identity.backup` — کلید بازیابی
- `fleet-cache.json` — آخرین فهرست گیت‌وی‌ها و پینگ‌ها (برای وقتی discovery آنلاین شکست می‌خورد)
- `runtime.json` — وضعیت نشست در حال اجرا، برای `status`

`runtime.json` فقط وضعیت است؛ `status` علاوه بر آن بررسی می‌کند که پروکسی واقعاً به پورت گوش می‌دهد و وضعیت کهنه را پاک می‌کند.

---

## عیب‌یابی

**`address already in use`**
یکی از پورت‌های ۱۰۸۰/۱۰۸۱ اشغال است. با `--listen` و `--http-listen` دو پورت آزاد بدهید یا برنامه اشغال‌کننده را ببندید.

**`no gateways found` / discovery شکست می‌خورد**
اتصال اینترنت و خروجی UDP را بررسی کنید. کلاینت ابتدا از دایرکتوری امضاشده و کش محلی استفاده می‌کند؛ اگر شبکه فیلتر است، `--stealth` را امتحان کنید یا با `--upstream` از یک پروکسی بالادستی رد شوید.

**با آپ‌استریم HTTP خطای «only carries TCP» می‌گیرم**
پروکسی HTTP فقط TCP تونل می‌کند. یا `--stealth` (wg-tls) بدهید، یا آپ‌استریم را `socks5://` کنید.

**`Stealth mode: this location offers no DPI-resistant transport`**
آن گیت‌وی `awg`/`wg-tls` ندارد. کشور دیگری انتخاب کنید یا `--auto` بدهید.

**`the entry hop cannot use wg-tls in multi-hop mode`**
برای مسیر ورودی ترنسپورت دیگری انتخاب کنید (مثلاً `--speed` یا گیت‌وی دیگری).

**`status` می‌گوید not running ولی پروسه بالاست**
`runtime.json` ممکن است کهنه باشد؛ `status` آن را خودکار پاک می‌کند. مطمئن شوید با همان کاربری اجرا می‌کنید که پروکسی را بالا آورده است.

**مرورگر کار می‌کند ولی برنامه‌ای نه**
آن برنامه از تنظیمات پروکسی سیستم استفاده نمی‌کند؛ باید SOCKS5/HTTP را دستی در خودش تنظیم کنید.

**تغییرات split یا config اعمال نمی‌شود**
تنظیمات هنگام شروع خوانده می‌شوند. پروکسی را دوباره اجرا کنید.

---

## توسعه

```bash
gofmt -l .          # باید خالی باشد
go build ./...
go vet ./...
```

برای انتشار نسخهٔ جدید، یک تگ نسخه بزنید و push کنید؛ workflow فقط باینری‌های ساخته‌شده را به Release اضافه می‌کند و خود فایل‌های کامپایل‌شده وارد ریپازیتوری نمی‌شوند:

```bash
git tag v0.1.0
git push origin v0.1.0
```

ساختار کد:

| فایل | نقش |
|---|---|
| `cli.go` | ورودی CLI، help، status، config، identity |
| `commands.go` | list، dns، split، favorites |
| `run.go` | مدیر نشست، انتخاب مسیر، reconnect، وضعیت runtime |
| `tunnel.go` | تونل WireGuard/AmneziaWG و مولتی‌هاپ |
| `bridge.go` | پل UDP↔TLS برای `wg-tls` |
| `upstream.go` | آپ‌استریم: SOCKS5/HTTP CONNECT، UDP ASSOCIATE و bind وایرگارد |
| `proxy.go` | SOCKS5/HTTP، مسیریابی split، kill switch |
| `api.go` | discovery از Flux، enroll، امضای پاسخ‌ها، DNS |
| `countries.go` | گروه‌بندی کشور/شهر و اندازه‌گیری پینگ |
| `keys.go` | کلیدها، base58، کلید بازیابی، PoW |
| `sign.go` | تأیید امضای Ed25519 و canonical JSON |
| `data/directory.json` | snapshot امضاشده دایرکتوری فلیت |

### نکته دربارهٔ دایرکتوری

فیلدهای `payment_address` و `price_flux` در `data/directory.json` و ساختار `Directory` فقط به این دلیل باقی مانده‌اند که امضای دایرکتوری روی کل سند محاسبه می‌شود. هیچ خروجی یا منطق کلاینت آن‌ها را نمی‌خواند.
