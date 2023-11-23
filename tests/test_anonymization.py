# -*- coding: utf-8 -*-
import unittest
from datetime import datetime
from datetime import timezone

from cloudproof_py.anonymization import DateAggregator
from cloudproof_py.anonymization import Hasher
from cloudproof_py.anonymization import NoiseGenerator
from cloudproof_py.anonymization import NumberAggregator
from cloudproof_py.anonymization import NumberScaler
from cloudproof_py.anonymization import WordMasker
from cloudproof_py.anonymization import WordPatternMasker
from cloudproof_py.anonymization import WordTokenizer


class TestHasher(unittest.TestCase):
    def test_sha2(self) -> None:
        hasher = Hasher("SHA2")
        res = hasher.apply_str("test sha2")
        self.assertEqual(res, "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=")

        hasher = Hasher("SHA2", b"example salt")
        res = hasher.apply_str("test sha2")
        self.assertEqual(res, "d32KiG7kpZoaU2/Rqa+gbtaxDIKRA32nIxwhOXCaH1o=")

    def test_sha3(self) -> None:
        hasher = Hasher("SHA3")
        res = hasher.apply_str("test sha3")
        self.assertEqual(res, "b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04/I=")

        hasher = Hasher("SHA3", b"example salt")
        res = hasher.apply_str("test sha3")
        self.assertEqual(res, "UBtIW7mX+cfdh3T3aPl/l465dBUbgKKZvMjZNNjwQ50=")

    def test_argon2(self) -> None:
        with self.assertRaises(Exception):
            # should fail without salt
            hasher = Hasher("Argon2")

        hasher = Hasher("Argon2", b"example salt")
        res = hasher.apply_str("low entropy data")
        self.assertEqual(res, "JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM=")


class TestNoiseGen(unittest.TestCase):
    def test_gaussian_float(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters("Gaussian", 0.0, 1.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        noise_generator = NoiseGenerator.new_with_bounds("Gaussian", -5.0, 5.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        with self.assertRaises(Exception):
            noise_generator = NoiseGenerator.new_with_parameters("Gaussian", 0.0, -1.0)

        with self.assertRaises(Exception):
            noise_generator = NoiseGenerator.new_with_bounds("Gaussian", 1.0, 0.0)

    def test_laplacian_float(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters("Laplace", 0.0, 1.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        noise_generator = NoiseGenerator.new_with_bounds("Laplace", -10.0, 10.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

    def test_uniform_float(self) -> None:
        noise_generator = NoiseGenerator.new_with_bounds("Uniform", -10.0, 10.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        with self.assertRaises(Exception):
            noise_generator = NoiseGenerator.new_with_parameters("Uniform", 1.0, 0.0)

    def test_gaussian_int(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters("Gaussian", 0.0, 1.0)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

        noise_generator = NoiseGenerator.new_with_bounds("Gaussian", -5, 5)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

    def test_laplacian_int(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters("Laplace", 0, 1)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

        noise_generator = NoiseGenerator.new_with_bounds("Laplace", -10, 10)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

    def test_uniform_int(self) -> None:
        noise_generator = NoiseGenerator.new_with_bounds("Uniform", -10, 10)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

    def test_gaussian_date(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters(
            "Gaussian", 0.0, 2.0 * 3600
        )
        noisy_date_str = noise_generator.apply_on_date("2023-04-07T12:34:56Z")

        dt = datetime.fromisoformat(noisy_date_str)
        self.assertEqual(dt.day, 7)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.year, 2023)

    def test_laplacian_date(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters("Laplace", 0, 2.0 * 3600)
        noisy_date_str = noise_generator.apply_on_date("2023-04-07T12:34:56Z")

        dt = datetime.fromisoformat(noisy_date_str)
        self.assertEqual(dt.day, 7)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.year, 2023)

    def test_uniform_date(self) -> None:
        noise_generator = NoiseGenerator.new_with_bounds(
            "Uniform", -10 * 3600, 10 * 3600
        )
        noisy_date_str = noise_generator.apply_on_date("2023-04-07T12:34:56Z")

        dt = datetime.fromisoformat(noisy_date_str)
        self.assertEqual(dt.day, 7)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.year, 2023)

    def test_correlated_noise_gaussian_floats(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters("Gaussian", 10.0, 2.0)
        values = [1.0, 1.0, 1.0]
        factors = [1.0, 2.0, 4.0]

        res = noise_generator.apply_correlated_noise_on_floats(values, factors)
        self.assertAlmostEqual(
            (res[0] - values[0]) * factors[1],
            (res[1] - values[1]) * factors[0],
            places=6,
        )
        self.assertAlmostEqual(
            (res[0] - values[0]) * factors[2],
            (res[2] - values[2]) * factors[0],
            places=6,
        )

    def test_correlated_noise_laplace_ints(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters("Laplace", 10.0, 2.0)
        values = [1, 1, 1]
        factors = [1.0, 2.0, 4.0]

        res = noise_generator.apply_correlated_noise_on_ints(values, factors)
        # Ordering only holds if noise is positive
        self.assertLessEqual(res[0], res[1])
        self.assertLessEqual(res[1], res[2])

    def test_correlated_noise_uniform_date(self) -> None:
        noise_generator = NoiseGenerator.new_with_bounds("Uniform", 0.0, 10.0)
        values = [
            "2023-05-02T00:00:00Z",
            "2023-05-02T00:00:00Z",
            "2023-05-02T00:00:00Z",
        ]
        factors = [1.0, 2.0, 4.0]
        noisy_values = noise_generator.apply_correlated_noise_on_dates(values, factors)

        date1 = datetime.fromisoformat(noisy_values[0])
        date2 = datetime.fromisoformat(noisy_values[1])
        date3 = datetime.fromisoformat(noisy_values[2])
        # Ordering only holds if noise is positive
        self.assertLessEqual(date1.second, date2.second)
        self.assertLessEqual(date2.second, date3.second)


class TestWordMasking(unittest.TestCase):
    def test_word_masker(self) -> None:
        word_masker = WordMasker(["quick", "brown", "dog"])
        data = "The Quick! brown fox, Jumps over the lazy dog."
        expected_result = "The XXXX! XXXX fox, Jumps over the lazy XXXX."
        self.assertEqual(expected_result, word_masker.apply(data))

    def test_word_tokenizer(self) -> None:
        word_tokenizer = WordTokenizer(["password", "secret"])
        text = "My password is secret"
        masked_text = word_tokenizer.apply(text)
        self.assertNotIn("password", masked_text)
        self.assertNotIn("secret", masked_text)

    def test_word_pattern_masker(self) -> None:
        pattern = r"\b\d{4}-\d{2}-\d{2}\b"
        replace_str = "DATE"
        masker = WordPatternMasker(pattern, replace_str)

        # Test case where pattern is present
        data = "On 2022-04-01, the company announced its plans for expansion."
        expected_output = "On DATE, the company announced its plans for expansion."
        self.assertEqual(masker.apply(data), expected_output)

        # Test case where pattern is not present
        data = "The quick brown fox jumps over the lazy dog."
        expected_output = "The quick brown fox jumps over the lazy dog."
        self.assertEqual(masker.apply(data), expected_output)

        # Invalid regex
        with self.assertRaises(Exception):
            WordPatternMasker("(", "XXX")


class TestAggregator(unittest.TestCase):
    def test_number_aggregator_with_invalid_exponent(self) -> None:
        with self.assertRaises(Exception):
            NumberAggregator(500)

    def test_number_aggregator_on_float(self):
        na = NumberAggregator(-2)
        self.assertEqual(na.apply_on_float(123.456789), "123.46")
        self.assertEqual(na.apply_on_float(0.001), "0.00")

        na = NumberAggregator(2)
        self.assertEqual(na.apply_on_float(123.456789), "100")

    def test_number_aggregator_on_int(self):
        na = NumberAggregator(3)
        self.assertEqual(na.apply_on_int(12345), "12000")
        self.assertEqual(na.apply_on_int(999), "1000")
        self.assertEqual(na.apply_on_int(499), "0")

    def test_date_aggregator(self):
        # Test rounding to the nearest minute
        aggregator = DateAggregator("Minute")
        rounded_date_str = aggregator.apply_on_date("2023-04-27T16:23:45Z")
        rounded_date = datetime.fromisoformat(rounded_date_str)
        expected_date = datetime(2023, 4, 27, 16, 23, 0, tzinfo=timezone.utc)
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest hour
        aggregator = DateAggregator("Hour")
        input_date_str = "2023-04-27T16:23:45+00:00"
        input_tz = datetime.fromisoformat(input_date_str).tzinfo
        rounded_date_str = aggregator.apply_on_date(input_date_str)
        rounded_date = datetime.fromisoformat(rounded_date_str)
        expected_date = datetime(2023, 4, 27, 16, 0, 0, tzinfo=input_tz)
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest day
        aggregator = DateAggregator("Day")
        input_date_str = "2023-04-27T16:23:45+01:00"
        input_tz = datetime.fromisoformat(input_date_str).tzinfo
        rounded_date_str = aggregator.apply_on_date(input_date_str)
        rounded_date = datetime.fromisoformat(rounded_date_str)
        expected_date = datetime(2023, 4, 27, 0, 0, 0, tzinfo=input_tz)
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest month
        aggregator = DateAggregator("Month")
        input_date_str = "2023-04-27T16:23:45-05:00"
        input_tz = datetime.fromisoformat(input_date_str).tzinfo
        rounded_date_str = aggregator.apply_on_date(input_date_str)
        rounded_date = datetime.fromisoformat(rounded_date_str)
        expected_date = datetime(2023, 4, 1, 0, 0, 0, tzinfo=input_tz)
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest year
        aggregator = DateAggregator("Year")
        rounded_date_str = aggregator.apply_on_date("2023-04-27T16:23:45Z")
        rounded_date = datetime.fromisoformat(rounded_date_str)
        expected_date = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(rounded_date, expected_date)

        with self.assertRaises(Exception):
            # Wrong input: missing timezone info at the end
            aggregator.apply_on_date("2023-04-27T16:23:45")

        # Wrong time unit
        with self.assertRaises(Exception):
            aggregator = DateAggregator("InvalidUnit")


class TestNumberScaler(unittest.TestCase):
    def test_apply_on_float(self):
        # Test with scaling factor of 2 and translation factor of 1
        scaler = NumberScaler(0, 1, 2, 1)
        self.assertAlmostEqual(scaler.apply_on_float(1.0), 3.0)
        self.assertAlmostEqual(scaler.apply_on_float(-1.0), -1.0)
        self.assertAlmostEqual(scaler.apply_on_float(0.0), 1.0)

        # Test with scaling factor of 0.5 and translation factor of 0
        scaler = NumberScaler(10, 1, 0.5, 0)
        self.assertAlmostEqual(scaler.apply_on_float(10.0), 0.0)
        self.assertAlmostEqual(scaler.apply_on_float(9.0), -0.5)
        self.assertAlmostEqual(scaler.apply_on_float(11.0), 0.5)

    def test_apply_on_int(self):
        # Test with scaling factor of 2 and translation factor of 1
        scaler = NumberScaler(0, 1, 2, 1)
        self.assertEqual(scaler.apply_on_int(1), 3)
        self.assertEqual(scaler.apply_on_int(-1), -1)
        self.assertEqual(scaler.apply_on_int(0), 1)

        # Test with scaling factor of 0.5 and translation factor of 0
        scaler = NumberScaler(10, 1, 0.5, 0)
        self.assertEqual(scaler.apply_on_int(10), 0)
        self.assertEqual(scaler.apply_on_int(9), -1)
        self.assertEqual(scaler.apply_on_int(11), 1)


if __name__ == "__main__":
    unittest.main()
