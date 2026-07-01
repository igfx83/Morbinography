import os
import json
import threading

from kivy.metrics import dp

os.environ.setdefault("KIVY_NO_ENV_CONFIG", "1")

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.core.text import LabelBase
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.modalview import ModalView
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen, ScreenManager, SlideTransition
from kivy.uix.scrollview import ScrollView
from kivy.effects.scroll import ScrollEffect
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput

from morbinography import Morbinography

_FONT_NAME = "NotoSans-Regular"
_FONT_PATH = os.path.join(os.getcwd(), "NotoSans-Regular.ttf")


def _register_font(path: str) -> bool:
    if not os.path.exists(path):
        return False

    try:
        with open(path, "rb") as f:
            header = f.read(4)

        if header not in (b"\x00\x01\x00\x00", b"true", b"ttcf"):
            raise ValueError("invalid font file header")

        LabelBase.register(name=_FONT_NAME, fn_regular=path)
        return True
    except Exception as exc:
        print(f"WARNING: unable to register font '{path}': {exc}")
        return False


_FONT_REGISTERED = _register_font(_FONT_PATH)


def _font_kwargs() -> dict:
    return {"font_name": _FONT_NAME} if _FONT_REGISTERED else {}

Window.clearcolor = (0.08, 0.08, 0.10, 1)

ACCENT = (0.18, 0.72, 0.56, 1)
ACCENT_DARK = (0.12, 0.52, 0.40, 1)
SURFACE = (0.14, 0.14, 0.18, 1)
TEXT = (0.92, 0.92, 0.92, 1)
WARN = (0.95, 0.70, 0.20, 1)
ERROR = (0.85, 0.25, 0.25, 1)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _btn(text, on_press=None, bg=ACCENT, size_hint_y=None, height=dp(52)):
    b = Button(
        text=text,
        size_hint_y=size_hint_y,
        height=height,
        background_normal="",
        background_color=bg,
        color=TEXT,
        font_size="16sp",
        bold=True,
        **_font_kwargs(),
    )
    if on_press:
        bind_fn = getattr(b, "bind", None)
        if callable(bind_fn):
            bind_fn(on_press=on_press)
    return b


def _label(text, color=TEXT, font_size="14sp", halign="left", **kw):
    l = Label(text=text, color=color, font_size=font_size, halign=halign, **_font_kwargs(), **kw)
    # Label has no wrap width by default (text_size=(None, None)), so long
    # text overflows its bounding box instead of wrapping. Bind text_size to
    # the widget's own width so halign/wrapping take effect, and keep it in
    # sync as the layout resizes.
    l.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None))) # pyright: ignore[reportAttributeAccessIssue]
    return l


def _input(hint="", multiline=False, **kw):
    return TextInput(
        hint_text=hint,
        multiline=multiline,
        background_color=SURFACE,
        foreground_color=TEXT,
        cursor_color=ACCENT,
        font_size="14sp",
        padding=[12, 10],
        **kw,
    )


def _clear_text_input_selection(*widgets):
    for widget in widgets:
        if widget is None:
            continue
        try:
            widget.cancel_selection()
        except Exception:
            pass
        try:
            widget._hide_handles()
        except Exception:
            pass
        try:
            widget.focus = False
        except Exception:
            pass


def _alert(title, message, color=TEXT):
    content = BoxLayout(orientation="vertical", padding=16, spacing=10)
    content.add_widget(_label(message, color=color, font_size="14sp", halign="center"))
    content.add_widget(_btn("OK", size_hint_y=None, height=dp(44),
                            on_press=lambda *_: popup.dismiss()))
    popup = Popup(
        title=title,
        content=content,
        size_hint=(0.85, 0.4),
        background_color=SURFACE,
        title_color=TEXT,
    )
    popup.open()


def _load_contacts():
    path = "config/contacts.json"
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_contact(name, key):
    path = "config/contacts.json"
    contacts = _load_contacts()
    contacts[name] = key
    with open(path, "w") as f:
        json.dump(contacts, f)


# ─────────────────────────────────────────────────────────────
# File picker modal
# ─────────────────────────────────────────────────────────────

def _picker_start_path():
    # /sdcard is the user-visible external storage where photos live on Android.
    sdcard = "/sdcard"
    if os.path.isdir(sdcard):
        return sdcard
    return os.path.expanduser("~")


def _request_storage_permission(callback):
    # On Android 13+ READ_EXTERNAL_STORAGE is ignored; READ_MEDIA_IMAGES is needed.
    # The permission callback fires on the Android UI thread, not Kivy's GL thread,
    # so we bounce back via Clock.schedule_once to avoid silent no-ops.
    try:
        from android.permissions import request_permissions, Permission  # type: ignore

        def _on_result(permissions, grants):
            Clock.schedule_once(lambda dt: callback(), 0)

        request_permissions(
            [Permission.READ_MEDIA_IMAGES, Permission.READ_EXTERNAL_STORAGE],
            _on_result,
        )
    except ImportError:
        callback()


class FilePicker(ModalView):
    def __init__(self, callback, filters=None, **kwargs):
        super().__init__(size_hint=(0.95, 0.85), background_color=SURFACE, **kwargs)
        self._callback = callback
        self._filters = filters

        # Show a waiting label until permissions are granted
        self._layout = BoxLayout(orientation="vertical", padding=8, spacing=8)
        self._waiting = _label("Requesting storage permission…",
                               halign="center", size_hint_y=None, height=dp(40))
        self._layout.add_widget(self._waiting)
        self.add_widget(self._layout)

        _request_storage_permission(self._build_chooser)

    def _build_chooser(self):
        self._layout.remove_widget(self._waiting)

        start = _picker_start_path()
        default_filters = [
            "*.png", "*.PNG", "*.jpg", "*.JPG", "*.jpeg", "*.JPEG",
            "*.bmp", "*.BMP", "*.tiff", "*.TIFF", "*.webp", "*.WEBP",
        ]
        self._chooser = FileChooserListView(
            filters=self._filters or default_filters,
            path=start,
            rootpath=start,
            show_hidden=False,
            dirselect=False,
        )
        self._layout.add_widget(self._chooser)

        self._path_label = _label(start, font_size="11sp",
                                  color=(0.5, 0.5, 0.5, 1),
                                  size_hint_y=None, height=dp(20))
        self._chooser.bind(path=lambda inst, val: setattr(self._path_label, "text", val))  # pyright: ignore[reportAttributeAccessIssue]
        self._layout.add_widget(self._path_label)

        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=8)
        row.add_widget(_btn("Cancel", on_press=lambda *_: self.dismiss()))
        row.add_widget(_btn("Select", on_press=self._select))
        self._layout.add_widget(row)

    def _select(self, *_):
        sel = self._chooser.selection
        if sel:
            self.dismiss()
            self._callback(sel[0])
        else:
            _alert("No file selected", "Please tap a file first.", color=WARN)

# ─────────────────────────────────────────────────────────────
# Home screen
# ─────────────────────────────────────────────────────────────

class HomeScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        root = BoxLayout(orientation="vertical", padding=40, spacing=24)

        root.add_widget(Label(size_hint_y=0.15))
        root.add_widget(
            Label(
                text="Morbinography",
                font_size="30sp",
                bold=True,
                color=ACCENT,
                size_hint_y=None,
                height=dp(60),
                **_font_kwargs(),
            )
        )
        root.add_widget(
            _label(
                "Hide encrypted messages inside ordinary images.",
                color=(0.65, 0.65, 0.65, 1),
                font_size="13sp",
                halign="center",
                size_hint_y=None,
                height=dp(36),
            )
        )
        root.add_widget(Label(size_hint_y=0.1))
        root.add_widget(
            _btn("  Encrypt a message", on_press=self._go_encrypt, height=dp(64), size_hint_y=None)
        )
        root.add_widget(
            _btn("  Decrypt an image", on_press=self._go_decrypt,
                 bg=SURFACE, height=dp(64), size_hint_y=None)
        )
        root.add_widget(Label(size_hint_y=0.1))
        root.add_widget(
            _btn("  Settings / My Keys", on_press=self._go_settings,
                 bg=SURFACE, height=dp(48), size_hint_y=None)
        )
        root.add_widget(Label())
        self.add_widget(root)

    def _go_encrypt(self, *_):
        self.manager.transition = SlideTransition(direction="left")
        self.manager.current = "encrypt"

    def _go_decrypt(self, *_):
        self.manager.transition = SlideTransition(direction="left")
        self.manager.current = "decrypt"

    def _go_settings(self, *_):
        self.manager.transition = SlideTransition(direction="left")
        self.manager.current = "settings"


# ─────────────────────────────────────────────────────────────
# Settings screen
# ─────────────────────────────────────────────────────────────

class SettingsScreen(Screen):
    def __init__(self, morb: Morbinography, **kw):
        super().__init__(**kw)
        self._morb = morb

        root = BoxLayout(orientation="vertical", padding=20, spacing=14,
                         size_hint_y=None, height=Window.height)
        root.bind(minimum_height=root.setter("height")) # pyright: ignore[reportAttributeAccessIssue]

        root.add_widget(Label(
            text="Settings / My Keys",
            font_size="20sp",
            bold=True,
            color=ACCENT,
            size_hint_y=None,
            height=dp(48),
            halign="center",
            valign="top",
            **_font_kwargs(),
        ))

        # ── My public key ──
        root.add_widget(_label("Your public key (share this with contacts):",
                               font_size="13sp", color=(0.6, 0.6, 0.6, 1),
                               size_hint_y=None, height=dp(24)))
        self._pub_key_input = TextInput(
            text=morb.public_key_pem(),
            multiline=True,
            readonly=True,
            background_color=SURFACE,
            foreground_color=TEXT,
            font_size="11sp",
            padding=[10, 8],
            size_hint_y=None,
            height=dp(180),
        )

        self._pub_key_input.bind(focus=self._on_pub_key_focus) # pyright: ignore[reportAttributeAccessIssue]
        Window.bind(on_touch_down=self._on_window_touch)
        root.add_widget(self._pub_key_input)

        # ── Regenerate ──
        root.add_widget(_btn("Generate new key pair", on_press=self._regen_keys,
                             bg=WARN, size_hint_y=None, height=dp(48)))

        # ── Import private key ──
        root.add_widget(_label("Import existing private key (PEM):",
                               font_size="13sp", color=(0.6, 0.6, 0.6, 1),
                               size_hint_y=None, height=dp(24)))
        root.add_widget(_label(
            "Paste your private key below to restore it on this device.",
            font_size="12sp", color=(0.5, 0.5, 0.5, 1),
            size_hint_y=None, height=dp(32),
        ))
        self._import_input = _input(
            hint="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
            multiline=True,
            size_hint_y=None,
            height=dp(180),
        )
        root.add_widget(self._import_input)
        root.add_widget(_btn("Import private key", on_press=self._import_key,
                             size_hint_y=None, height=dp(48)))

        root.add_widget(_btn("⬅ Back", on_press=self._go_back,
                             bg=SURFACE, size_hint_y=None, height=dp(44)))

        self.add_widget(root)

    def _on_pub_key_focus(self, instance, has_focus):
        if not has_focus:
            _clear_text_input_selection(instance)

    def _on_window_touch(self, instance, touch):
        if self._pub_key_input is not None and self._pub_key_input.focus:
            if not self._pub_key_input.collide_point(*self._pub_key_input.to_local(*touch.pos)):
                _clear_text_input_selection(self._pub_key_input)
        if self._import_input is not None and self._import_input.focus:
            if not self._import_input.collide_point(*self._import_input.to_local(*touch.pos)):
                _clear_text_input_selection(self._import_input)
        return False

    def on_pre_leave(self, *args):
        _clear_text_input_selection(self._pub_key_input, self._import_input)
        return super().on_pre_leave(*args)

    def _go_back(self, *_):
        # Android's selection handles/highlight can survive a focus loss that
        # happens via screen transition rather than a touch, since no
        # on_touch_down ever lands outside the TextInput to clear it.
        _clear_text_input_selection(self._pub_key_input)
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current = "home"

    def _regen_keys(self, *_):
        content = BoxLayout(orientation="vertical", padding=16, spacing=10)
        content.add_widget(_label(
            "This will replace your current key pair.\n"
            "Anyone with your old public key cannot encrypt to you anymore, "
            "and existing encrypted messages will be unreadable.",
            color=WARN, halign="center", size_hint_y=None, height=dp(80),
        ))

        def _confirm(*_):
            popup.dismiss()
            self._morb.regenerate_keys()
            self._pub_key_input.text = self._morb.public_key_pem()
            _alert("Done", "New key pair generated and saved.", color=ACCENT)

        row = BoxLayout(size_hint_y=None, height=dp(44), spacing=8)
        row.add_widget(_btn("Cancel", on_press=lambda *_: popup.dismiss(), bg=SURFACE))
        row.add_widget(_btn("Regenerate", on_press=_confirm, bg=ERROR))
        content.add_widget(row)

        popup = Popup(title="Confirm key regeneration", content=content,
                      size_hint=(0.88, 0.45), background_color=SURFACE, title_color=WARN)
        popup.open()

    def _import_key(self, *_):
        pem = self._import_input.text.strip()
        if not pem:
            _alert("Nothing to import", "Paste your private key PEM first.", color=WARN)
            return
        try:
            self._morb.import_key(pem)
            self._pub_key_input.text = self._morb.public_key_pem()
            self._import_input.text = ""
            _alert("Imported", "Private key imported and saved.", color=ACCENT)
        except Exception as e:
            _alert("Import failed", str(e), color=ERROR)


# ─────────────────────────────────────────────────────────────
# Encrypt screen
# ─────────────────────────────────────────────────────────────

class EncryptScreen(Screen):
    def __init__(self, morb: Morbinography, **kw):
        super().__init__(**kw)
        self._morb = morb
        self._image_path = None

        scroll = ScrollView(effect_cls=ScrollEffect, do_scroll_x=False)
        root = BoxLayout(orientation="vertical", padding=20, spacing=14,
                         size_hint_y=None)
        root.bind(minimum_height=root.setter("height")) # pyright: ignore[reportAttributeAccessIssue]

        root.add_widget(_label("Step 1 — Choose a cover image", font_size="13sp",
                               color=(0.6, 0.6, 0.6, 1), size_hint_y=None, height=dp(24)))
        self._img_label = _label("No image selected", size_hint_y=None, height=dp(28))
        root.add_widget(self._img_label)
        root.add_widget(_btn("Browse images…", on_press=self._pick_image,
                             size_hint_y=None, height=dp(48)))

        self._warn_label = _label("", color=WARN, size_hint_y=None, height=dp(0))
        root.add_widget(self._warn_label)

        root.add_widget(_label("Step 2 — Type your message", font_size="13sp",
                               color=(0.6, 0.6, 0.6, 1), size_hint_y=None, height=dp(24)))
        self._msg_input = _input(hint="Your secret message…", multiline=True,
                                 size_hint_y=None, height=dp(100))
        root.add_widget(self._msg_input)

        self._capacity_label = _label("", color=(0.5, 0.5, 0.5, 1),
                                      size_hint_y=None, height=dp(22))
        root.add_widget(self._capacity_label)

        root.add_widget(_label("Step 3 — Choose recipient", font_size="13sp",
                               color=(0.6, 0.6, 0.6, 1), size_hint_y=None, height=dp(24)))

        self._contacts = _load_contacts()
        contact_names = ["Paste key manually…"] + list(self._contacts.keys())
        self._contact_spinner = Spinner(
            text=contact_names[0],
            values=contact_names,
            size_hint_y=None,
            height=dp(44),
            background_normal="",
            background_color=SURFACE,
            color=TEXT,
        )
        self._contact_spinner.bind(text=self._on_contact_selected) # pyright: ignore[reportAttributeAccessIssue]
        root.add_widget(self._contact_spinner)

        self._key_input = _input(
            hint="Paste recipient's public key (PEM) here…",
            multiline=True,
            size_hint_y=None,
            height=dp(110),
        )
        # Long-press needs more time than ScrollView's default scroll_timeout
        # to win against the scroll gesture, or Android's paste bubble never
        # gets a chance to show.
        scroll.scroll_timeout = 400
        self._key_input.bind(focus=self._on_key_input_focus) # pyright: ignore[reportAttributeAccessIssue]
        Window.bind(on_touch_down=self._on_window_touch)
        root.add_widget(self._key_input)

        root.add_widget(_btn("Encrypt & Save", on_press=self._run_encrypt,
                             size_hint_y=None, height=dp(56)))

        self._status_label = _label("", size_hint_y=None, height=dp(30))
        root.add_widget(self._status_label)

        row = BoxLayout(size_hint_y=None, height=dp(44), spacing=8)
        row.add_widget(_btn("⬅ Back", on_press=self._go_back_encrypt,
                            bg=SURFACE, size_hint_y=None, height=dp(44)))
        root.add_widget(row)

        scroll.add_widget(root)
        self.add_widget(scroll)

    def _on_key_input_focus(self, instance, has_focus):
        if not has_focus:
            _clear_text_input_selection(instance)

    def _on_window_touch(self, instance, touch):
        for widget in (self._msg_input, self._key_input):
            if widget is not None and widget.focus:
                if not widget.collide_point(*widget.to_local(*touch.pos)):
                    _clear_text_input_selection(widget)
                    break
        return False

    def on_pre_leave(self, *args):
        _clear_text_input_selection(self._msg_input, self._key_input)
        return super().on_pre_leave(*args)

    def _go_back_encrypt(self, *_):
        # Android's selection handles/highlight can survive a focus loss that
        # happens via screen transition rather than a touch, since no
        # on_touch_down ever lands outside the TextInput to clear it.
        _clear_text_input_selection(self._key_input, self._msg_input)
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current = "home"

    def _pick_image(self, *_):
        FilePicker(callback=self._on_image_selected).open()

    def _on_image_selected(self, path):
        try:
            _, was_converted, original_fmt = self._morb.set_image(path)
            self._image_path = path
            fname = os.path.basename(path)
            self._img_label.text = fname

            if was_converted:
                self._warn_label.text = (
                    f"Note: {original_fmt} is a lossy format. "
                    "The image will be converted to PNG before encoding. "
                    "Use a PNG source for best results."
                )
                self._warn_label.height = dp(52)
            else:
                self._warn_label.text = ""
                self._warn_label.height = dp(0)

            self._capacity_label.text = (
                f"This image can hold up to {self._morb.image_capacity} characters."
            )
        except ValueError as e:
            _alert("Unsupported file", str(e), color=ERROR)

    def _on_contact_selected(self, spinner, text):
        if text != "Paste key manually…":
            self._key_input.text = self._contacts.get(text, "")
        else:
            self._key_input.text = ""

    def _run_encrypt(self, *_):
        if not self._image_path:
            _alert("No image", "Please choose a cover image first.", color=WARN)
            return
        msg = self._msg_input.text.strip()
        if not msg:
            _alert("No message", "Please type a message to hide.", color=WARN)
            return
        key = self._key_input.text.strip()
        if not key:
            _alert("No key", "Please select a contact or paste a public key.", color=WARN)
            return

        self._status_label.text = "Encrypting…"
        self._status_label.color = ACCENT

        def _work():
            try:
                encrypted_msg, data = self._morb.binary_encryption(msg, key)
                out_image = self._morb.modify_elements(
                    self._morb.image.copy(), encrypted_msg, data # pyright: ignore[reportOptionalMemberAccess]
                )
                out_dir = (
                    "/sdcard/Pictures/Morbinography"
                    if os.path.isdir("/sdcard")
                    else "outputs"
                )
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(
                    out_dir,
                    "encrypted_" + os.path.splitext(os.path.basename(self._image_path))[0] + ".png"
                )
                out_image.save(out_path)
                Clock.schedule_once(lambda dt: self._on_success(out_path))

                contacts = _load_contacts()
                if key not in contacts.values():
                    Clock.schedule_once(lambda dt: self._prompt_save_contact(key))
            except Exception as e:
                err = str(e)
                Clock.schedule_once(lambda dt, err=err: self._on_error(err))

        threading.Thread(target=_work, daemon=True).start()

    def _on_success(self, out_path):
        self._status_label.text = ""
        _alert("Done!", f"Encrypted image saved to:\n{out_path}", color=ACCENT)

    def _on_error(self, msg):
        self._status_label.text = ""
        _alert("Encryption failed", msg, color=ERROR)

    def _prompt_save_contact(self, key):
        content = BoxLayout(orientation="vertical", padding=16, spacing=10)
        content.add_widget(_label("Save this public key as a contact?",
                                  halign="center", size_hint_y=None, height=dp(32)))
        name_input = _input(hint="Contact name…", size_hint_y=None, height=dp(44))
        content.add_widget(name_input)

        def _save(*_):
            name = name_input.text.strip()
            if name:
                _save_contact(name, key)
                self._contacts = _load_contacts()
                self._contact_spinner.values = (
                    ["Paste key manually…"] + list(self._contacts.keys())
                )
            popup.dismiss()

        row = BoxLayout(size_hint_y=None, height=dp(44), spacing=8)
        row.add_widget(_btn("Skip", on_press=lambda *_: popup.dismiss(), bg=SURFACE))
        row.add_widget(_btn("Save", on_press=_save))
        content.add_widget(row)

        popup = Popup(title="Save Contact", content=content,
                      size_hint=(0.85, 0.45), background_color=SURFACE, title_color=TEXT)
        popup.open()


# ─────────────────────────────────────────────────────────────
# Decrypt screen
# ─────────────────────────────────────────────────────────────

class DecryptScreen(Screen):
    def __init__(self, morb: Morbinography, **kw):
        super().__init__(**kw)
        self._morb = morb
        self._image_path = None

        root = BoxLayout(orientation="vertical", padding=20, spacing=16)

        root.add_widget(_label("Choose an image to decrypt", font_size="13sp",
                               color=(0.6, 0.6, 0.6, 1), size_hint_y=None, height=dp(24)))
        self._img_label = _label("No image selected", size_hint_y=None, height=dp(28))
        root.add_widget(self._img_label)
        root.add_widget(_btn("Browse images…", on_press=self._pick_image,
                             size_hint_y=None, height=dp(48)))

        root.add_widget(_btn("Decrypt", on_press=self._run_decrypt,
                             size_hint_y=None, height=dp(56)))

        self._result_label = _label("", size_hint_y=None, height=dp(0))
        scroll = ScrollView(effect_cls=ScrollEffect, do_scroll_x=False, size_hint_y=0.45)
        scroll.add_widget(self._result_label)
        root.add_widget(scroll)

        root.add_widget(Label())
        root.add_widget(_btn("⬅ Back", on_press=self._go_back,
                             bg=SURFACE, size_hint_y=None, height=dp(44)))

        self.add_widget(root)

    def _go_back(self, *_):
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current = "home"

    def _pick_image(self, *_):
        FilePicker(callback=self._on_image_selected).open()

    def _on_image_selected(self, path):
        try:
            self._morb.set_image(path)
            self._image_path = path
            self._img_label.text = os.path.basename(path)
            self._result_label.text = ""
            self._result_label.height = dp(0)
        except ValueError as e:
            _alert("Unsupported file", str(e), color=ERROR)

    def _run_decrypt(self, *_):
        if not self._image_path:
            _alert("No image", "Please choose an image to decrypt.", color=WARN)
            return

        self._result_label.text = "Decrypting…"
        self._result_label.color = ACCENT
        self._result_label.height = dp(30)

        def _work():
            try:
                morb = Morbinography()
                morb.set_image(self._image_path)
                retrieved = morb.retrieve_data(morb.image)
                decrypted_data = morb.decrypt_with_aes(*retrieved)
                message = morb.retrieve_elements(morb.image.copy(), decrypted_data) # pyright: ignore[reportOptionalMemberAccess]
                Clock.schedule_once(lambda dt: self._on_success(message))
            except Exception as e:
                err = str(e)
                Clock.schedule_once(lambda dt, err=err: self._on_error(err))

        threading.Thread(target=_work, daemon=True).start()

    def _on_success(self, message):
        self._result_label.text = message
        self._result_label.color = ACCENT
        self._result_label.height = max(dp(80), len(message) // 2)

    def _on_error(self, msg):
        self._result_label.text = f"Could not decrypt: {msg}"
        self._result_label.color = ERROR
        self._result_label.height = dp(60)


# ─────────────────────────────────────────────────────────────
# App entry point
# ─────────────────────────────────────────────────────────────

class MorbinographyApp(App):
    def build(self):
        morb = Morbinography()
        sm = ScreenManager()
        sm.add_widget(HomeScreen(name="home"))
        sm.add_widget(SettingsScreen(morb, name="settings"))
        sm.add_widget(EncryptScreen(morb, name="encrypt"))
        sm.add_widget(DecryptScreen(morb, name="decrypt"))
        return sm


if __name__ == "__main__":
    MorbinographyApp().run()
