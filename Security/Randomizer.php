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
 * This class allows you to generate strong random data easily -- something that you can't do with PHP natively.
 * It has been designed to work with multiple environments and provides a handful set of extra methods.
 * This class has been written performance in mind meaning that it is not resource intensive.
 * In fact, generating a lot of random data can be a lot faster with this library compared to things like mt_rand().
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class Randomizer
{
	const GENERATOR_CAPICOM = 'capicom';
	const GENERATOR_CSP = 'csp';
	const GENERATOR_DEV_URANDOM = 'dev_urandom';
	const GENERATOR_GNUPG = 'gnupg';
	const GENERATOR_OPENSSL = 'openssl';
	const GENERATOR_OPENSSL_FUNCTION = 'openssl_function';

	// Pointers stored for later use. Enhances performance a bit.
	private static $csp;
	private static $capicom;

	/**
	 * This property tells the random generator that was used for the last random data generation process.
	 * @var string
	 */
	public static $generatorUsed = null;

	/**
	 * This property tells whether the previous call to generate random data produced *strong* random data.
	 * @var bool
	 */
	public static $producedStrongRandomData = false;

	/**
	 * This is a static class and requires no initialization.
	 */
	private function __construct()
	{
	}

	/**
	 * No cloning available, either.
	 */
	private function __clone()
	{
	}

	/**
	 * Returns a random token in hex format. The length is in bytes.
	 * @param int $length The length in bytes.
	 * @return string
	 */
	public static function getRandomToken($length)
	{
		return bin2hex(self::getRandomBytes($length));
	}

	/**
	 * Returns a random boolean value.
	 *
	 * @return bool
	 */
	public static function getRandomBoolean()
	{
		$randomByte = self::getRandomBytes(1);

		return (ord($randomByte) + 1) % 2 ? true : false;
	}

	/**
	 * Returns a random integer between the given range.
	 *
	 * @param int $min
	 * @param int $max
	 * @return int
	 */
	public static function getRandomInteger($min, $max)
	{
		if ($min >= $max)
			throw new Exception('The maximum value cannot be equal or smaller than the minimum value.');

		$float = self::getRandomFloat();
		$integer = $min + round($float * ($max - $min));

		return (int) $integer;
	}

	/**
	 * Returns a random float between 0 and 1.
	 *
	 * @return float
	 */
	public static function getRandomFloat()
	{
		// TODO: Don't throw away the half of the byte 6, instead store it for the next use.

		// PHP uses double precision floating-point format (64-bit) for its floats.
		// They include 52-bits of significand precision, which is 6.5 bytes.
		// Therefore, we need to gather 7 bytes of random data, and throw the last 4-bits away.

		$bytes = self::getRandomBytes(7);
		$bytes[6] = $bytes[6] & chr(15); // AND the 7th byte with a 0x0F (0000 1111).
		$bytes .= chr(0); // Add a NULL byte for easier further calculations.

		// V2 = unsigned long (32-bit), we want to unpack two of those = 64-bits = 7 bytes + the NULL byte.
		$parts = unpack('V2', $bytes);

		// Create a single number out of the unpacked data.
		// The second unsigned long has 20-bits of significant information, so, we need to adjust it.
		$number = $parts[1] + pow(2.0, 32) * $parts[2];

		// Create the floating point number.
		$number /= pow(2.0, 52);

		return (float) $number;
	}

	/**
	 * Generates and returns a random GUID. The total number of unique keys 3.4×10^38 makes sure
	 * that it is extremely unlikely to generate two identical GUIDs. As a comparison, there are
	 * approximately 1.33×10^50 atoms on earth.
	 *
	 * @return string
	 */
	public static function getRandomGUID()
	{
		$hex = strtoupper(bin2hex(self::getRandomBytes(16)));

		return substr($hex,0,8) . '-' . substr($hex,8,4) . '-' . substr($hex,12,4) . '-' . substr($hex,16,4) . '-' . substr($hex,20,12);
	}

	/**
	 * This method generates strong random data.
	 *
	 * @param int $length The length in bytes.
	 * @return binary
	 */
	public static function getRandomBytes($length)
	{
		// Cast to an integer.
		$length = (int) $length;

		if ($length < 1)
			throw new Exception('Length cannot be less than 1 byte.');

		// Initialize this.
		self::$producedStrongRandomData = true;

		// If the developer has specified a constant, we use that generator directly, if possible.
		if (defined('PSL_RANDOM_GENERATOR') && PSL_RANDOM_GENERATOR !== null)
		{
			$random = '';

			switch (PSL_RANDOM_GENERATOR)
			{
				case self::GENERATOR_CAPICOM:
					$random = self::generateUsingCapicom($length);
					break;
				case self::GENERATOR_CSP:
					$random = self::generateUsingCsp($length);
					break;
				case self::GENERATOR_DEV_URANDOM:
					$random = self::generateUsingDeviceUnlockedRandom($length);
					break;
				case self::GENERATOR_GNUPG:
					$random = self::generateUsingGnuPg($length);
					break;
				case self::GENERATOR_OPENSSL:
					$random = self::generateUsingOpenSsl($length);
					break;
				case self::GENERATOR_OPENSSL_FUNCTION:
					$random = self::generateUsingOpenSslFunction($length);
					break;
			}

			if ($random !== "")
				return $random;

			// The chosen generator failed.
			trigger_error("\PSL\Randomizer failed to use the generator '" . PSL_RANDOM_GENERATOR . "' eventhough it was chosen.", E_USER_WARNING);
		}

		$isWindows = stripos(PHP_OS, 'WIN') === 0 ? true : false;

		// The methods used in Windows vs Unix are different a little bit.
		// Also, the order of methods is different for optimal performance.

		if ($isWindows)
		{
			$random = self::generateUsingCapicom($length);
			if ($random !== "")
				return $random;

			$random = self::generateUsingOpenSsl($length);
			if ($random !== "")
				return $random;

			$random = self::generateUsingGnuPg($length);
			if ($random !== "")
				return $random;

			$random = self::generateUsingOpenSslFunction($length);
			if ($random !== "")
				return $random;
		}
		else
		{
			$random = self::generateUsingOpenSslFunction($length);
			if ($random !== "")
				return $random;

			$random = self::generateUsingDeviceUnlockedRandom($length);
			if ($random !== "")
				return $random;

			$random = self::generateUsingOpenSsl($length);
			if ($random !== "")
				return $random;

			$random = self::generateUsingGnuPg($length);
			if ($random !== "")
				return $random;
		}

		return self::generateUsingFallback($length);
	}

	/**
	 * Uses native functions found in PHP as a fallback method to generate pseudo random data.
	 *
	 * @param int $length
	 * @return binary
	 */
	private static function generateUsingFallback($length)
	{
		self::$producedStrongRandomData = false;

		// Set the previously used generator.
		self::$generatorUsed = null;

		// Trigger a warning.
		trigger_error("\PSL\Randomizer could not generate strong random data.", E_USER_WARNING);

		$random = '';
		for ($a = 0; $a < $length; $a++)
		{
			// A twisted generalized feedback shift register called the Mersenne Twister.
			$source = mt_rand();

			// In addition to the Mersenne Twister, we use a good old Linear Congruential Generator.
			$source += bcmul(lcg_value(), pow(2, 52)) & 0xFF;

			// µ-second is a non-random number.
			$usec = explode('.', microtime(true));
			end($usec);
			$source += (int) $usec & 0xFF;

			// This is pretty predictable, but is somewhat non-deterministic.
			$source += memory_get_usage() & 0xFF;

			// Same as above, lacks of unpredictability.
			$source += getmypid() & 0xFF;

			// Let's make it a byte.
			$random .= chr($source % 256);
		}

		return (binary) $random;
	}

	/**
	 * Uses Microsoft's Cryptographic Application Programming Interface (CAPI) via COM.
	 * Works on Windows when CAPICOM SDK has been installed and the DLL registered.
	 *
	 * Returns an empty string upon failure.
	 *
	 * @param int $length
	 * @return binary
	 */
	private static function generateUsingCapicom($length)
	{
		if (class_exists('COM', false))
		{
			try
			{
				if (is_resource(self::$capicom) === false)
					self::$capicom = new \COM('CAPICOM.Utilities.1');

				$random = base64_decode(self::$capicom->getrandom($length, 0));

				// Set the previously used generator.
				self::$generatorUsed = self::GENERATOR_CAPICOM;

				// The value of $random could be null, our casting makes it an empty string.
				return (binary) $random;
			}
			catch (\Exception $e)
			{
			}
		}

		return "";
	}

	/**
	 * Produces high quality random bytes using .NET framework.
	 *
	 * This functionality is deprecated as there seems to be a bug in PHP's VARIANTs.
	 *
	 * Returns an empty string upon failure.
	 *
	 * @deprecated
	 * @param int $length
	 * @return binary
	 */
	private static function generateUsingCsp($length)
	{
		trigger_error("The random generator 'CSP' is deprecated.", E_USER_DEPRECATED);
		return "";

		if (class_exists('DOTNET'))
		{
			try
			{
				if (is_resource(self::$csp) === false)
					self::$csp = new \DOTNET("mscorlib", "System.Security.Cryptography.RNGCryptoServiceProvider");

				// Create an array with a length of $length filled with null bytes.
				$array = array_fill(0, $length, chr(0));

				// Since there's no support for byte arrays, we need to use variants.
				$variant = new \VARIANT($array, VT_UI1);

				// Gather the bytes.
				self::$csp->GetBytes($variant);

				// Set the previously used generator.
				self::$generatorUsed = self::GENERATOR_CSP;

				return (binary) implode('', $array);
			}
			catch (Exception $e)
			{
			}
		}

		return "";
	}

	/**
	 * Works on systems that have OpenSSL installed, PHP 5.3 and OpenSSL extension loaded.
	 *
	 * Returns an empty string upon failure.
	 *
	 * @param int $length
	 * @return binary
	 */
	private static function generateUsingOpenSslFunction($length)
	{
		if (function_exists('openssl_random_pseudo_bytes'))
		{
			$random = openssl_random_pseudo_bytes($length, $strong);

			if ($strong)
			{
				// Set the previously used generator.
				self::$generatorUsed = self::GENERATOR_OPENSSL_FUNCTION;

				return (binary) $random;
			}
		}

		return "";
	}

	/**
	 * Requires OpenSSL, system() function and the installation path to be in the env PATH.
	 *
	 * Returns an empty string upon failure.
	 *
	 * @param int $length
	 * @return binary
	 */
	private static function generateUsingOpenSsl($length)
	{
		$random = Executor::shell_exec('openssl rand', $length);

		// Set the previously used generator.
		self::$generatorUsed = self::GENERATOR_OPENSSL;

		// The value of $random could be null, our casting makes it an empty string.
		return (binary) $random;
	}

	/**
	 * Requires GnuPG, system() function and the installation path to be in the env PATH.
	 *
	 * Returns an empty string upon failure.
	 *
	 * @param int $length
	 * @return binary
	 */
	private static function generateUsingGnuPg($length)
	{
		$random = Executor::shell_exec('gpg --gen-random 0', $length);

		// Set the previously used generator.
		self::$generatorUsed = self::GENERATOR_GNUPG;

		// The value of $random could be null, our casting makes it an empty string.
		return (binary) $random;
	}

	/**
	 * Works on Sun Solaris, Unix and Linux systems.
	 *
	 * @param int $length
	 * @return binary
	 */
	private static function generateUsingDeviceUnlockedRandom($length)
	{
		$random = '';

		// Open the handler.
		$fp = @fopen('/dev/urandom', 'rb');

		// Read the bytes.
		if ($fp)
		{
			// For optimal performance, we want to have unbuffered reads.
			if (function_exists('stream_set_read_buffer'))
				stream_set_read_buffer($fp, 0);

			$random = fread($fp, $length);
			fclose($fp);

			// Set the previously used generator.
			self::$generatorUsed = self::GENERATOR_DEV_URANDOM;
		}

		return (binary) $random;
	}

	/**
	 * Determines the best random generator to use in this platform.
	 */
	public static function determineBestRandomGenerator()
	{
		// We generate one byte of random data.
		self::getRandomBytes(1);

		return self::$generatorUsed;
	}
}
