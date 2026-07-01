from dependencies import *

with open("config/morse_dict.json", "r") as f:
    morse_code = json.load(f)


class Morbinography:

    def __init__(self, img_path=None, key_pair=None):
        self.__img_path = img_path
        self.__element_manifest = []
        self.__element_manifest_set = set()
        self.image = None
        self.image_capacity = None
        self.__seed = None
        try:
            load_dotenv()
        except AttributeError:
            # find_dotenv() walks the call stack via sys._getframe(), which
            # returns frames with no .f_back on Android's python-for-android
            # runtime. No .env is bundled in the APK anyway, so skip it.
            pass
        self.private_key, self.public_key = self.__initialize_keys(key_pair)
        with open("config/deck.json", "r") as f:
            self.__deck = json.load(f)

    @staticmethod
    def _key_path():
        storage = os.getenv("ANDROID_PRIVATE") or "."
        return os.path.join(storage, "private_key.pem")

    def __initialize_keys(self, key_pair):
        if key_pair:
            private_key = RSA.import_key(key_pair)
            return private_key, private_key.publickey()
        path = self._key_path()
        if os.path.exists(path):
            with open(path, "rb") as f:
                private_key = RSA.import_key(f.read())
        else:
            private_key = self.__generate_key_pair()
        return private_key, private_key.publickey()

    def __generate_key_pair(self):
        private_key = RSA.generate(2048)
        path = self._key_path()
        with open(path, "wb") as f:
            f.write(private_key.export_key(format="PEM", pkcs=8))
        return private_key

    def import_key(self, pem: str):
        private_key = RSA.import_key(pem.strip())
        path = self._key_path()
        with open(path, "wb") as f:
            f.write(private_key.export_key(format="PEM", pkcs=8))
        self.private_key = private_key
        self.public_key = private_key.publickey()

    def regenerate_keys(self):
        private_key = self.__generate_key_pair()
        self.private_key = private_key
        self.public_key = private_key.publickey()

    def public_key_pem(self) -> str:
        return self.public_key.export_key(format="PEM").decode("utf-8")

    def __set_seed(self, aes_key):
        self.__seed = (self.image.size[0] * self.image.size[1]) % sum(aes_key)

    # ──────────────────────────────────────────────────────────────────────────
    # Deck: shuffled deterministically from the AES key, then hashed to produce
    # the CBC IV. Both sides can reproduce this from the wrapped AES key alone,
    # so the deck shuffle is now a real second factor in the IV derivation rather
    # than decorative noise.
    # ──────────────────────────────────────────────────────────────────────────

    def __shuffle_deck_from_key(self, aes_key: bytes) -> list:
        rng = random.Random(aes_key)
        deck = self.__deck.copy()
        rng.shuffle(deck)
        return deck

    def __derive_iv_from_deck(self, shuffled_deck: list) -> bytes:
        return hashlib.sha256("".join(shuffled_deck).encode()).digest()[:16]

    # ──────────────────────────────────────────────────────────────────────────
    # Start coordinate derivation.
    # On encrypt: derive (x, y) from the AES key and image dimensions, then
    # store them as a 4-pixel fixed header at (0,0)-(0,3) so decryption can
    # locate the spiral without a key. The header pixels are the only fixed
    # anchor point; everything else is key-derived.
    # ──────────────────────────────────────────────────────────────────────────

    def __derive_start_coords(self, aes_key: bytes) -> tuple[int, int]:
        w, h = self.image.size
        # Use first two key bytes, biased away from the header strip (col 0)
        x = max(1, aes_key[0] % w)
        y = max(1, aes_key[1] % h)
        return x, y

    def __write_coord_header(self, img, x: int, y: int):
        # Encode x and y as 16-bit values across 4 pixels (2 pixels × 8 bits each)
        # Each pixel's red channel LSB carries one bit; we use 16 pixels total
        # but pack tightly: pixels (0,0)..(0,15) carry the 16-bit x, (0,16)..(0,31) carry y.
        for bit_idx, (val, row_offset) in enumerate(
            [(x, 0), (y, 16)]
        ):
            for b in range(16):
                px = list(img.getpixel((0, row_offset + b)))
                bit = (val >> (15 - b)) & 1
                px[0] = (px[0] & ~1) | bit
                img.putpixel((0, row_offset + b), tuple(px))

    def __read_coord_header(self, img) -> tuple[int, int]:
        coords = []
        for row_offset in [0, 16]:
            val = 0
            for b in range(16):
                px = img.getpixel((0, row_offset + b))
                val = (val << 1) | (px[0] & 1)
            coords.append(val)
        return coords[0], coords[1]

    def __encrypt_with_aes(self, data, recipient_key):
        aes_key = os.urandom(32)
        shuffled_deck = self.__shuffle_deck_from_key(aes_key)
        iv = self.__derive_iv_from_deck(shuffled_deck)
        self.__set_seed(aes_key)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        oaep = PKCS1_OAEP.new(recipient_key, hashAlgo=SHA256)
        encrypted_key = oaep.encrypt(aes_key)
        # IV is not stored separately — it's reproducible from the wrapped key
        return encrypted_data, encrypted_key

    def decrypt_with_aes(self, encrypted_data, encrypted_key):
        try:
            oaep = PKCS1_OAEP.new(self.private_key, hashAlgo=SHA256)
            aes_key = oaep.decrypt(bytes(encrypted_key))
            shuffled_deck = self.__shuffle_deck_from_key(aes_key)
            iv = self.__derive_iv_from_deck(shuffled_deck)
            self.__set_seed(aes_key)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(bytes(encrypted_data))
            return unpad(decrypted_padded, AES.block_size)
        except Exception as e:
            print("Decryption failed:", str(e))
            raise

    def __find_indices(self, keys_1, keys_2):
        return [keys_1.index(key) if key in keys_1 else -1 for key in keys_2]

    def binary_encryption(self, msg, recipient_key=None):
        original = list(morse_code.keys())
        keys = original.copy()
        secrets.SystemRandom().shuffle(keys)
        codex = self.__find_indices(original, keys)
        encrypted_msg = ""

        for char in msg:
            if char == " ":
                encrypted_msg += "000000"
            else:
                lookup_char = char.upper()
                if lookup_char in morse_code:
                    encrypted_msg += "1" if char.islower() else "0"
                    doo_dahs = morse_code[original[codex[original.index(lookup_char)]]]
                    for doo in doo_dahs:
                        encrypted_msg += "10" if doo == "." else "1110"
                    encrypted_msg += "00"

        encrypted_msg_length = len(encrypted_msg)
        data_to_encrypt = (
            str(encrypted_msg_length).encode() + b"|" + str(codex).encode()
        )

        recipient_key = RSA.import_key(
            recipient_key.replace("\\n", "\n").encode("utf-8")
        )

        encrypted_data, encrypted_key = self.__encrypt_with_aes(
            data_to_encrypt, recipient_key
        )
        return encrypted_msg, (encrypted_data, encrypted_key)

    def set_image(self, img_path):
        img, was_converted, original_fmt = self.__load_as_png(img_path)
        self.image = img
        self.__calculate_capacity(self.image)
        self.__img_path = img_path
        return self.image, was_converted, original_fmt

    # ──────────────────────────────────────────────────────────────────────────
    # Image loading with format check and PNG conversion.
    # JPEG is accepted but warned — lossy compression may have already degraded
    # pixel values before we see the image, which matters for existing steg data
    # but is fine for fresh encryption on a clean source image.
    # ──────────────────────────────────────────────────────────────────────────

    LOSSLESS_FORMATS = {"PNG", "BMP", "TIFF", "WEBP", "GIF"}
    LOSSY_FORMATS = {"JPEG", "JPG"}
    # Formats Pillow can open but can't reliably convert to lossless RGB PNG
    UNSUPPORTED_FORMATS = {"PDF", "EPS"}

    def __load_as_png(self, img_path: str) -> tuple:
        try:
            img = Image.open(img_path)
        except Exception as e:
            raise ValueError(f"Cannot open image: {e}")

        fmt = (img.format or "").upper()

        if fmt in self.UNSUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported file type: {fmt}. "
                "Only raster image formats (PNG, JPEG, BMP, TIFF, WEBP) are accepted."
            )

        was_converted = fmt not in self.LOSSLESS_FORMATS
        original_fmt = fmt

        # Normalise to RGB PNG — drops alpha channel if present (RGBA → RGB)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        elif img.mode != "RGB":
            img = img.convert("RGB")

        return img, was_converted, original_fmt

    def __calculate_capacity(self, img):
        width, height = img.size
        total_bytes = width * height * 3
        # Reserve 32 pixels on column 0 for the coord header
        capacity = ((total_bytes // 8) // 1.5) - 32
        self.image_capacity = int(capacity)

    def __advance_spiral(self, img, x: int, y: int, direction_index: int, visited: set):
        directions = [(1, 0), (0, 1), (-1, 0), (0, -1)]
        for _ in range(4):
            dx, dy = directions[direction_index]
            nx, ny = x + dx, y + dy
            if 0 <= nx < img.width and 0 <= ny < img.height and (nx, ny) not in visited:
                return nx, ny, direction_index
            direction_index = (direction_index + 1) % 4
        raise RuntimeError("No valid spiral direction found")

    def __embed_data(self, img, data, start_x: int, start_y: int):
        self.__element_manifest = []
        header_pixels = {(0, r) for r in range(32)}
        self.__element_manifest_set = set(header_pixels)

        bits = "".join(format(b, "08b") for b in data[0]) + "".join(
            format(b, "08b") for b in data[1]
        )
        first_byte = format(len(bits), "012b")
        bits = first_byte + bits

        directions = [(1, 0), (0, 1), (-1, 0), (0, -1)]
        x, y, direction_index = start_x, start_y, 0
        i = 0
        while i < len(bits):
            pixel = list(img.getpixel((x, y)))
            for j in range(3):
                if i >= len(bits):
                    break
                if bits[i] == "1" and pixel[j] % 2 == 0:
                    pixel[j] += 1
                elif bits[i] == "0" and pixel[j] % 2 != 0:
                    pixel[j] -= 1
                i += 1
            self.__element_manifest.append(((x, y), tuple(pixel)))
            self.__element_manifest_set.add((x, y))
            img.putpixel((x, y), tuple(pixel))

            x, y, direction_index = self.__advance_spiral(
                img, x, y, direction_index, self.__element_manifest_set
            )

    def modify_elements(self, image, msg, data):
        if self.__seed is None:
            raise Exception("Seed is required — call binary_encryption first")

        # Derive start coords from AES key embedded in encrypted envelope.
        # We recover the AES key from the wrapped key for coord derivation only;
        # the envelope hasn't been written to the image yet so we use the private
        # key if available (self-send), otherwise derive from the raw key bytes
        # already set during __encrypt_with_aes via __set_seed.
        # Coords are derived from the first 2 bytes of the encrypted_key blob —
        # this is public (RSA ciphertext) and deterministic per session.
        encrypted_key_bytes = bytes(data[1])
        start_x = max(1, encrypted_key_bytes[0] % image.width)
        start_y = max(1, encrypted_key_bytes[1] % image.height)

        self.__write_coord_header(image, start_x, start_y)
        self.__embed_data(image, data, start_x, start_y)

        random.seed(self.__seed)
        a = np.asarray(image)
        all_indices = [(i, j) for i in range(a.shape[1]) for j in range(a.shape[0])]
        # Exclude header pixels (column 0, rows 0-31) and spiral pixels
        header_pixels = {(0, r) for r in range(32)}
        filtered_indices = [
            idx for idx in all_indices
            if idx not in self.__element_manifest_set and idx not in header_pixels
        ]
        if len(msg) > len(filtered_indices):
            raise ValueError("Message is too long for the given image.")

        indices = random.sample(filtered_indices, k=len(msg))

        for j, (x, y) in enumerate(indices):
            pixel = list(image.getpixel((x, y)))
            total = sum(pixel[:3])
            if (total % 2 == 0 and msg[j] == "1") or (total % 2 != 0 and msg[j] == "0"):
                for i in range(3):
                    if pixel[i] < 255:
                        pixel[i] += 1
                    else:
                        pixel[i] -= 1
            image.putpixel((x, y), tuple(pixel))

        return image

    def retrieve_data(self, image):
        self.__element_manifest = []
        header_pixels = {(0, r) for r in range(32)}
        self.__element_manifest_set = set(header_pixels)

        # Pass 1: read coord header from fixed anchor pixels
        start_x, start_y = self.__read_coord_header(image)

        # Pass 2: spiral from derived coords to extract encrypted envelope
        x, y, direction_index = start_x, start_y, 0
        bits = ""
        while len(bits) < 12 or len(bits) < int(bits[:12], 2) + 12:
            pixel = image.getpixel((x, y))
            for j in range(3):
                bits += str(pixel[j] % 2)
            self.__element_manifest.append(((x, y), tuple(pixel)))
            self.__element_manifest_set.add((x, y))
            x, y, direction_index = self.__advance_spiral(
                image, x, y, direction_index, self.__element_manifest_set
            )

        data_length = int(bits[:12], 2)
        bits = bits[12: 12 + data_length]
        encoded = []
        num_bytes = len(bits) // 8
        for b in range(num_bytes):
            byte = bits[b * 8: b * 8 + 8]
            if byte:
                encoded.append(int(byte, 2))
            else:
                break

        # Last 256 bytes are the RSA-wrapped AES key (2048-bit key = 256 bytes)
        return encoded[:-256], encoded[-256:]

    def __parse_decrypted_data(self, decrypted_data):
        decoded_str = decrypted_data.decode()
        parts = decoded_str.split("|")
        length = int(parts[0])
        codex = ast.literal_eval(parts[1])
        return length, codex

    def retrieve_elements(self, img, data):
        random.seed(self.__seed)
        length, codex = self.__parse_decrypted_data(data)
        original = list(morse_code.keys())
        reversed_codex = {k: v for k, v in zip(codex, original)}

        a = np.asarray(img)
        all_indices = [(i, j) for i in range(a.shape[1]) for j in range(a.shape[0])]
        header_pixels = {(0, r) for r in range(32)}
        filtered_indices = [
            idx for idx in all_indices
            if idx not in self.__element_manifest_set and idx not in header_pixels
        ]
        indices = random.sample(filtered_indices, k=length)

        msg_bits = ""
        for (x, y) in indices:
            pixel = list(img.getpixel((x, y)))
            total = sum(pixel[:3])
            msg_bits += "0" if total % 2 == 0 else "1"

        decrypted_msg = ""
        morse_char = ""
        doo_dahs = list(morse_code.values())
        while len(msg_bits) > 0:
            if msg_bits.startswith("000000"):
                decrypted_msg += " "
                msg_bits = msg_bits[6:]
                continue

            case_marker = msg_bits[0]
            msg_bits = msg_bits[1:]
            morse_char = ""
            while len(msg_bits) > 0:
                if msg_bits.startswith("10"):
                    morse_char += "."
                    msg_bits = msg_bits[2:]
                elif msg_bits.startswith("1110"):
                    morse_char += "-"
                    msg_bits = msg_bits[4:]
                elif msg_bits.startswith("00"):
                    if morse_char in doo_dahs:
                        index = doo_dahs.index(morse_char)
                        char = reversed_codex[index]
                        decrypted_msg += char.lower() if case_marker == "1" else char
                    morse_char = ""
                    msg_bits = msg_bits[2:]
                    break

        return decrypted_msg
