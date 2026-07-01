[app]
title = Morbinography
package.name = morbinography
package.domain = org.morbinography

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,ttf
source.include_patterns = fonts/*.ttf

# Entry point
source.main = app.py

version = 1.0.0

# ── Dependencies ──────────────────────────────────────────────────────────────
# cryptography has C extensions — we pull it via the p4a recipe.
# numpy and Pillow also have pre-built recipes in python-for-android.
requirements = python3,kivy,pillow,numpy,pycryptodome,python-dotenv

# ── Orientation / display ─────────────────────────────────────────────────────
orientation = portrait
fullscreen = 0

# ── Android specifics ─────────────────────────────────────────────────────────
android.minapi = 24
android.api = 36
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a

# Required for file picker access (scoped storage + legacy)
android.permissions = READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, READ_MEDIA_IMAGES

# Allow writing to external storage on older Android versions
android.allow_backup = True

# p4a bootstrap — SDL2 is the standard for Kivy
p4a.bootstrap = sdl2

# Pin p4a to a release that ships Python 3.12 — v2026.05.09 pulls 3.14 which
# breaks cryptography/cffi/pyo3 cross-compilation against the NDK.
p4a.branch = v2024.01.21

# ── Icons / presplash (replace with real assets) ──────────────────────────────
# icon.filename = assets/icon.png
# presplash.filename = assets/presplash.png

# ── Build config ──────────────────────────────────────────────────────────────
[buildozer]
log_level = 2
warn_on_root = 1
