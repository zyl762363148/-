from io import BytesIO
import unittest

from PIL import Image

from analyze_content import (
    analyze_image_bytes,
    automation_headers,
    difference_hash,
    dominant_palette,
    require_sites_bypass_token,
)


class AnalyzeContentTests(unittest.TestCase):
    def test_generates_stable_bounded_pixel_evidence(self):
        image = Image.new("RGB", (1200, 1920))
        pixels = image.load()
        for y in range(image.height):
            for x in range(image.width):
                pixels[x, y] = (x * 255 // image.width, y * 255 // image.height, 96)
        buffer = BytesIO()
        image.save(buffer, format="JPEG", quality=90)

        first = analyze_image_bytes(buffer.getvalue())
        second = analyze_image_bytes(buffer.getvalue())
        self.assertEqual(first["perceptualHash"], second["perceptualHash"])
        self.assertRegex(first["perceptualHash"], r"^[a-f0-9]{16}$")
        self.assertEqual((first["width"], first["height"]), (1200, 1920))
        self.assertGreaterEqual(len(first["palette"]), 1)
        self.assertLessEqual(len(first["palette"]), 5)
        self.assertEqual(set(first["metrics"]), {
            "sharpness", "contrast", "clipping", "safeArea", "watermarkRisk"
        })
        self.assertTrue(all(0 <= value <= 100 for value in first["metrics"].values()))

    def test_hash_and_palette_accept_monochrome_art(self):
        image = Image.new("L", (9, 8), 128)
        self.assertEqual(difference_hash(image), "0000000000000000")
        palette = dominant_palette(image.convert("RGB"))
        self.assertEqual(palette, ["#808080"])

    def test_private_sites_requests_use_two_independent_authorization_headers(self):
        headers = automation_headers("a" * 32, "b" * 32)
        self.assertEqual(headers["Authorization"], f"Bearer {'a' * 32}")
        self.assertEqual(headers["OAI-Sites-Authorization"], f"Bearer {'b' * 32}")
        self.assertNotIn("a" * 32, "https://liuli.example/api/automation/content-analysis")
        self.assertNotIn("b" * 32, "https://liuli.example/api/automation/content-analysis")

    def test_sites_bypass_is_optional_for_public_sites_and_validated_when_present(self):
        self.assertEqual(
            require_sites_bypass_token("https://liuli.example.chatgpt.site", ""),
            "",
        )
        with self.assertRaisesRegex(SystemExit, "LIULI_SITES_BYPASS_TOKEN"):
            require_sites_bypass_token("https://liuli.example.chatgpt.site", "short")
        self.assertEqual(require_sites_bypass_token("https://localhost.example", ""), "")


if __name__ == "__main__":
    unittest.main()
