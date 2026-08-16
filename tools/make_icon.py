"""สร้าง icon ของ RDPGuard (โล่สีน้ำเงิน + กุญแจ) — ใช้ Pillow เฉพาะตอน dev.

รัน:  python tools/make_icon.py
ผลลัพธ์: assets/icon.ico (16-256px) + assets/icon-256.png
"""

import os

from PIL import Image, ImageDraw, ImageFilter

SIZE = 256
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")

# สีจาก DESIGN.md (accent น้ำเงิน)
C_TOP = (92, 168, 235)     # ฟ้าอ่อน (บนโล่)
C_BOTTOM = (12, 86, 168)   # น้ำเงินเข้ม (ล่างโล่)
C_BORDER = (9, 58, 116)    # ขอบโล่
C_LOCK = (250, 252, 255)   # กุญแจ
C_KEYHOLE = (13, 60, 108)  # รูกุญแจ

SHIELD = [
    (128, 8),
    (238, 42),
    (238, 132),
    (238, 164),
    (196, 206),
    (128, 250),
    (60, 206),
    (18, 164),
    (18, 132),
    (18, 42),
]


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def make_icon():
    os.makedirs(OUT_DIR, exist_ok=True)

    # ---- พื้นหลังโปร่งใส ----
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # ---- mask รูปโล่ ----
    mask = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(mask).polygon(SHIELD, fill=255)

    # ---- gradient แนวตั้ง (ฟ้า -> น้ำเงินเข้ม) ----
    grad = Image.new("RGB", (SIZE, SIZE))
    gd = ImageDraw.Draw(grad)
    for y in range(SIZE):
        gd.line([(0, y), (SIZE, y)], fill=lerp(C_TOP, C_BOTTOM, y / SIZE))

    # ---- เงาเบา ๆ ใต้โล่ (เพิ่มมิติ) ----
    shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    shadow_pts = [(p[0], p[1] + 10) for p in SHIELD]
    sd.polygon(shadow_pts, fill=(0, 0, 0, 60))
    shadow = shadow.filter(ImageFilter.GaussianBlur(12))
    img.alpha_composite(shadow)

    # ---- ตัวโล่ (gradient ผ่าน mask) ----
    shield_layer = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    shield_layer.paste(grad, (0, 0), mask)
    img.alpha_composite(shield_layer)

    # ---- ขอบโล่ ----
    draw.polygon(SHIELD, outline=C_BORDER + (255,), width=9)

    # ---- เส้นไฮไลต์บนโล่ (มันวาวนิด ๆ) ----
    hi = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    hid = ImageDraw.Draw(hi)
    top_pts = [(p[0], p[1]) for p in SHIELD if p[1] <= 120]
    hid.polygon(top_pts + [(128, 120)], fill=(255, 255, 255, 26))
    img.alpha_composite(hi)

    # ---- กุญแจ (ห่วง + ตัว + รูกุญแจ) ----
    lock = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    ld = ImageDraw.Draw(lock)

    # ห่วง (U-shape)
    ld.arc([94, 76, 162, 144], 180, 360, fill=C_LOCK + (255,), width=16)
    ld.line([(94, 116), (94, 132)], fill=C_LOCK + (255,), width=16)
    ld.line([(162, 116), (162, 132)], fill=C_LOCK + (255,), width=16)

    # ตัวกุญแจ (rounded rect)
    ld.rounded_rectangle([88, 126, 168, 196], radius=18, fill=C_LOCK + (255,))

    # รูกุญแจ (วงกลม + หางตรง)
    ld.ellipse([116, 142, 140, 166], fill=C_KEYHOLE + (255,))
    ld.rectangle([121, 156, 135, 176], fill=C_KEYHOLE + (255,))

    img.alpha_composite(lock)

    # ---- บันทึกหลายขนาด ----
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(os.path.join(OUT_DIR, "icon.ico"), sizes=sizes)
    img.save(os.path.join(OUT_DIR, "icon-256.png"))
    print("icon ที่: " + OUT_DIR)


if __name__ == "__main__":
    make_icon()
