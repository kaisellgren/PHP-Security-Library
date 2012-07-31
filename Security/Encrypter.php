<?php

/**
 * PHP Security Library.
 *
 * @author Kai Sellgren
 * @copyright Copyright (C) Kai Sellgren 2010
 * @package PHP Security Library
 * @since Version 1.00
 * @license http://opensource.org/licenses/lgpl-3.0.html GNU Lesser General Public License
 */

namespace PSL;

/**
 * This class provides useful methods for encryption, hashing, signing and the likes.
 * While some of the functionality are not exactly about "encryption", they are closely related.
 * TODO: Consider renaming this class to something more general like "Crypto".
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class Encrypter
{
	/**
	 * This method hashes given input data known as the preimage.
	 * It provides a simple yet effective iteration capability.
	 *
	 * @param string $algorithm
	 * @param mixed $input
	 * @param int $iterations
	 * @param bool $rawOutput
	 * @return mixed
	 */
	public static function hash($algorithm, $input, $iterations = 1, $rawOutput = false)
	{
		if ($iterations < 1)
			throw new Exception('There must be at least one iteration.');

		while ($iterations--)
		{
			// Note that we return the raw output of the hash algorithm inside the loop,
			// because it is more logical and it is easier to provide the fourth parameter to this method.
			$input = hash($algorithm, $input, true);
		}

		return ($rawOutput ? (binary) $input : bin2hex($input));
	}

	/**
	 * A method for calculating a hash message authentication code.
	 *
	 * @param string $algorithm
	 * @param mixed $input
	 * @param mixed $key
	 * @param int $iterations
	 * @param bool $rawOutput
	 * @return mixed
	 */
	public static function hmac($algorithm, $input, $key, $iterations = 1, $rawOutput = false)
	{
		if ($iterations < 1)
			throw new Exception('There must be at least one iteration.');

		while ($iterations--)
		{
			// Note that we return the raw output of the hash algorithm inside the loop,
			// because it is more logical and it is easier to provide the fourth parameter to this method.
			$input = hash_hmac($algorithm, $input, $key, true);
		}

		return ($rawOutput ? (binary) $data : bin2hex($input));
	}

	/**
	 * This method encrypts data and returns a CipherText object. You need it to decrypt the data back.
	 *
	 * @param string $cipher The cipher algorithm to use.
	 * @param mixed $plainText The plaintext to encrypt.
	 * @param binary $key An optional key. If not specified, PSL will generate it and return it within CipherText.
	 * @param string $operationMode The cipher mode of operation to use. Defaults to CBC.
	 * @param binary $iv An optional parameter. PSL will generate it if not given and return it within CipherText.
	 * @throws Exception
	 * @return \PSL\CipherText
	 */
	public static function encrypt($cipher, $plainText, $key = null, $operationMode = 'cbc', $iv = null)
	{
		$operationMode = strtolower($operationMode);

		// If the key is null, we generate it on ourself.
		if ($key === null)
		{
			// Check whether the cipher is supported.
			$supportedCiphers = self::getSupportedCiphers();
			if (in_array($cipher, $supportedCiphers) === false)
				throw new Exception("The cipher '$cipher' is not supported on this system. The following is a list of supported ciphers: " . implode(', ', $supportedCiphers));

			// We will use the maximum strength.
			$length = mcrypt_module_get_algo_key_size($cipher);
			$key = Randomizer::getRandomBytes($length);
		}

		// Make sure we can actually encrypt with these details. Be strict.
		self::isCipherable($cipher, $key, $operationMode, true);

		// If the developer did not specify an IV, we generate a strong pseudo random one.
		if ($iv === null)
		{
			if (($ivSize = @mcrypt_get_iv_size($cipher, $operationMode)) === false)
				throw new Exception("Could not retrieve an IV size for cipher '$cipher' using a operation mode '$operationMode'.");

			$iv = Randomizer::getRandomBytes($ivSize);
		}

		// Padding for block cipher modes such as CBC and ECB.
		$padded = false;
		if (mcrypt_module_is_block_mode($operationMode) === true)
		{
			$padded = true;

			// Calculate how many bytes we need to add.
			$addBytes = $ivSize - (strlen((binary) $plainText) % $ivSize);

			if ($addBytes === 0) // Important.
				$addBytes = $ivSize;

			// Pad with chr($addBytes).
			$plainText .= str_repeat(chr($addBytes), $addBytes);
		}

		// The encryption.
		if (($cipherText = @mcrypt_encrypt($cipher, $key, $plainText, $operationMode, $iv)) === false)
			throw new Exception("Could not encrypt with a cipher '$cipher' using a operation mode '$operationMode'.");

		// Building the object with the right properties and returning it.
		$ct = new CipherText();

		$ct->cipherText = $cipherText;
		$ct->iv = $iv;
		$ct->operationMode = $operationMode;
		$ct->cipher = $cipher;
		$ct->key = $key;
		$ct->padded = $padded; // In case some one needs to know this.

		return $ct;
	}

	/**
	 * This method decrypts ciphertext into plaintext.
	 *
	 * @param \PSL\CipherText $cipherTextObject
	 * @param binary $key
	 * @return binary
	 */
	public static function decrypt(CipherText $cipherTextObject, $key)
	{
		// TODO: Accept JSON encoded string?

		// The decryption.
		$cipher = $cipherTextObject->cipher;
		$operationMode = $cipherTextObject->operationMode;
		$cipherText = $cipherTextObject->cipherText;
		$iv = $cipherTextObject->iv;

		// Make sure we have everything.
		if ($iv === null || $cipher === null || $operationMode === null || $cipherText === null)
			throw new Exception("Could not decrypt because one or more details of these were missing: cipher, block mode, cipher text, iv. Please specify all of them.");

		// Make sure we can actually decrypt using these details.
		self::isCipherable($cipher, $key, $operationMode, true);

		if (($plainText = (binary) @mcrypt_decrypt($cipher, $key, $cipherText, $operationMode, $iv)) == false)
			throw new Exception("Could not decrypt with a cipher '$cipher' using a block mode '$operationMode'.");

		// Handling the padding for block cipher modes such as CBC and ECB.
		if (@mcrypt_module_is_block_mode($operationMode) === true)
		{
			$textSize = strlen($plainText);
			$amountOfPadding = ord($plainText[$textSize-1]);
			$plainText = substr($plainText, 0, $textSize - $amountOfPadding);
		}

		return (binary) $plainText;
	}

	/**
	 * Checks whether the given arguments are good to be used for encryption/decryption.
	 *
	 * @param string $cipher
	 * @param binary $key
	 * @param string $operationMode
	 * @param bool $strict Whether to true exceptions upon failure. Defaults to false.
	 * @throws Exception
	 * @return bool
	 */
	public static function isCipherable($cipher, $key, $operationMode, $strict = false)
	{
		// Check whether the cipher is supported.
		$supportedCiphers = self::getSupportedCiphers();
		if (in_array($cipher, $supportedCiphers) === false)
		{
			if ($strict === true)
				throw new Exception("The cipher '$cipher' is not supported on this system. The following is a list of supported ciphers: " . implode(', ', $supportedCiphers));

			return false;
		}

		// Check whether the block mode is supported.
		$supportedModes = self::getSupportedModes();
		if (in_array($operationMode, $supportedModes) === false)
		{
			if ($strict === true)
				throw new Exception("The block mode '$operationMode' is not supported on this system. The following is a list of supported operation modes: " . implode(', ', $supportedModes));

			return false;
		}

		// We discourage ECB.
		if ($operationMode === 'ecb')
			trigger_error("You should not use 'ecb' as your block mode due to its low strength.", E_USER_WARNING);

		// Make sure the key size is okay.
		$supportedKeySizes = mcrypt_module_get_supported_key_sizes($cipher);
		$keySize = strlen((binary) $key);
		if (in_array($keySize, $supportedKeySizes) === false)
		{
			if ($strict === true)
				throw new Exception("The cipher '$cipher' does not support a key size of '$keySize'. The following is a list of supported key sizes for '$cipher': " . implode(', ', $supportedKeySizes));

			return false;
		}

		// Make sure the person is not mixing non-block cipher modes with block ciphers and vice versa.
		if (mcrypt_module_is_block_algorithm($cipher) === true)
		{
			// He must be using also a block algorithm mode.
			if (mcrypt_module_is_block_algorithm_mode($operationMode) === false)
			{
				if ($strict === true)
					throw new Exception("You cannot encrypt with a block algorithm like '$cipher' using a non-block algorithm mode '$operationMode'.");

				return false;
			}
		}
		else
		{
			// He must be using a non-block algorithm mode.
			if (mcrypt_module_is_block_algorithm_mode($operationMode) === true)
			{
				if ($strict === true)
					throw new Exception("You cannot encrypt with a non-block algorithm like '$cipher' using a block algorithm mode '$operationMode'.");

				return false;
			}
		}
	}

	/**
	 * Computes a signature for the given data.
	 *
	 * @param mixed $data
	 * @param mixed $key
	 * @param string $algorithm
	 * @return string
	 */
	public function sign($data, $key, $algorithm = 'SHA1')
	{
		$algorithm = constant('OPENSSL_ALGO_' . strtoupper($algorithm));

		$pKey = openssl_get_privatekey($key);
		openssl_sign($data, $signature, $pKey, $algorithm);
		openssl_free_key($pKey);

		return $signature;
	}

	public static function verify()
	{

	}

	/**
	 * Returns an array of supported ciphers.
	 *
	 * @return array
	 */
	public static function getSupportedCiphers()
	{
		return mcrypt_list_algorithms();
	}

	/**
	 * Returns an array of supported operation modes.
	 *
	 * @return array
	 */
	public static function getSupportedModes()
	{
		return mcrypt_list_modes();
	}

	/**
	 * Creates a strong key out of the password.
	 * Key Derivation Function
	 */
	public static function passwordToKey()
	{
	}
}