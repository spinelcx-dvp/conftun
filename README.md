# 🚀 Config Scanner Panel

پنل خودکار جمع‌آوری و تست کانفیگ‌های V2Ray با GitHub Actions.

## 📋 نحوه کار

1. **GitHub Actions** هر ۱۰ دقیقه `scanner.py` رو اجرا می‌کنه
2. اسکنر کانفیگ‌ها رو از منابع (`sources.json`) جمع می‌کنه
3. کانفیگ‌های جدید رو در بچ‌های ۱۰ تایی تست می‌کنه
4. نتایج در `results.json` ذخیره و به ریپو push می‌شه
5. **GitHub Pages** پنل `index.html` رو نمایش می‌ده

## 🔧 راه‌اندازی

### ۱. فعال‌سازی GitHub Pages
- برو به **Settings → Pages**
- Source: **Deploy from a branch**
- Branch: **main** / **root**
- Save کن

### ۲. فعال‌سازی Workflow
- برو به تب **Actions**
- اگه پیام «Workflows aren't being run on this forked repository» دیدی، دکمه **Enable** رو بزن
- از منوی چپ **Config Scanner** رو انتخاب کن
- دکمه **Run workflow** رو بزن تا اولین بار اجرا شه

### ۳. تنظیم منابع
فایل `sources.json` رو ویرایش کن و URL های دلخواهت رو اضافه کن.

## 📊 ساختار فایل‌ها

| فایل | توضیح |
|------|-------|
| `scanner.py` | موتور اسکن و تست |
| `sources.json` | لیست منابع |
| `index.html` | پنل کاربری (GitHub Pages) |
| `results.json` | کانفیگ‌های فعال (خودکار) |
| `tested.json` | لیست تست‌شده‌ها (خودکار) |
| `requirements.txt` | پکیج‌ها |
| `.github/workflows/scanner.yml` | تنظیمات Actions |

## ⚙️ تنظیمات اسکنر

توی `scanner.py` قابل تغییرن:

```python
BATCH_SIZE = 10              # تعداد کانفیگ در هر بچ
TIMEOUT = 5                  # ثانیه timeout برای هر تست
MAX_CONFIGS_TO_TEST = 200    # حداکثر کانفیگ در هر اجرا
