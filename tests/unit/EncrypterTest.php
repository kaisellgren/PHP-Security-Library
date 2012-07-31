<?php

require_once 'PHPUnit/Framework.php';
require_once 'Security/Encrypter.php';
require_once 'Security/Randomizer.php';
require_once 'Security/CipherText.php';

class EncrypterTest extends PHPUnit_Framework_TestCase
{
	public function testEncryption()
	{
		$availableCiphers = PSL\Encrypter::getSupportedCiphers();
		$availableModes = PSL\Encrypter::getSupportedModes();

		$e = new PSL\Encrypter;

		$key = 'a test key';
		$plainText = 'some plain text';

		foreach ($availableCiphers as $cipher)
		{
			foreach ($availableModes as $mode)
			{
				$cipherText = $e->encrypt($cipher, $key, $plainText, $mode);
				if ($cipherText != false)
				{
					$plainTextDeciphered = $e->decrypt($cipherText, $key);
					$this->assertTrue($plainText === $plainTextDeciphered, "Deciphered text did not match ($cipher, $mode)!");
				}
			}
		}
	}
}