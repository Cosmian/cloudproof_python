# -*- coding: utf-8 -*-
import os
import unittest

from cloudproof_py.fpe import Alphabet, Float, Integer

KEY_LENGTH = 32
KEY = os.urandom(KEY_LENGTH)
TWEAK = os.urandom(1024)


class TestFpe(unittest.TestCase):
    """
    A unit test case for the Alphabet encryption and decryption methods.
    """

    def test_credit_card_numbers(self) -> None:
        """
        FPE on credit card numbers
        """
        alphabet = Alphabet("numeric")

        for credit_card_number in [
            "1234-1234-1234-1234",
            "0000-0000-0000-0000",
            "1234-5678-9012-3456",
        ]:
            ciphertext = alphabet.encrypt(KEY, TWEAK, credit_card_number)
            cleartext = alphabet.decrypt(KEY, TWEAK, ciphertext)
            assert len(credit_card_number) == len(ciphertext)
            assert cleartext == credit_card_number

    def test_chinese_text(self) -> None:
        """
        FPE on chinese text
        """
        alphabet = Alphabet("chinese")

        for chinese_text in [
            "天地玄黄 宇宙洪荒",
            "日月盈昃 辰宿列张",
            "寒来暑往 秋收冬藏",
        ]:
            ciphertext = alphabet.encrypt(KEY, TWEAK, chinese_text)
            cleartext = alphabet.decrypt(KEY, TWEAK, ciphertext)
            assert len(chinese_text) == len(ciphertext)
            assert cleartext == chinese_text

    def test_utf_text(self) -> None:
        """
        FPE on utf text
        """
        alphabet = Alphabet("utf")

        for utf_text in [
            "Bérangère Aigüe",
            "ПРС-ТУФХЦЧШЩЪЫЬ ЭЮЯаб-вгдежз ийклмнопрст уфхцчш",
            "吢櫬䀾羑襃￥",
        ]:
            ciphertext = alphabet.encrypt(KEY, TWEAK, utf_text)
            cleartext = alphabet.decrypt(KEY, TWEAK, ciphertext)
            assert len(utf_text) == len(ciphertext)
            assert cleartext == utf_text

    def test_custom_alphabet(self) -> None:
        """
        FPE with custom alphabet: adding the special characters /@&* to
        the alpha numeric alphabet
        """
        alphabet = Alphabet("alpha_numeric")
        alphabet.extend_with("/@&*")

        for custom_alphabet_text in [
            "Bérangère Aigüe 1234-&@",
            "@@@@",
            "&&&&&&&&&&&&&&&&&&",
        ]:
            ciphertext = alphabet.encrypt(KEY, TWEAK, custom_alphabet_text)
            cleartext = alphabet.decrypt(KEY, TWEAK, ciphertext)
            assert len(custom_alphabet_text) == len(ciphertext)
            assert cleartext == custom_alphabet_text

    def test_numbers(self) -> None:
        """
        FPE on numbers.
        """
        itg = Integer(10, 10)

        for my_integer in [
            1,
            12,
            1234567890,
        ]:
            ciphertext = itg.encrypt(KEY, TWEAK, my_integer)
            cleartext = itg.decrypt(KEY, TWEAK, ciphertext)
            assert cleartext == my_integer

    def test_big_numbers(self) -> None:
        """
        FPE on numbers and big numbers.
        """
        big_int = Integer(10, 100)
        for my_big_integer in [
            "1",
            "12",
            "1234567890",
            "123456789012345678901234567890",
            "1234567890123456789012345678901234567890",
            "12345678901234567890123456789012345678901234567890",
        ]:
            ciphertext = big_int.encrypt_big(KEY, TWEAK, my_big_integer)
            cleartext = big_int.decrypt_big(KEY, TWEAK, ciphertext)
            assert cleartext == my_big_integer

    def test_floats(self) -> None:
        """
        FPE on floats
        """
        flt = Float()

        for my_float in [
            -1.0,
            123456.0,
            123456.123456,
        ]:
            ciphertext = flt.encrypt(KEY, TWEAK, my_float)
            cleartext = flt.decrypt(KEY, TWEAK, ciphertext)
            assert cleartext == my_float


if __name__ == "__main__":
    unittest.main()
