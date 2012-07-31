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

/**
 * This class represents a key pair.
 *
 * Requires OpenSSL.
 */
class Security_KeyPair
{
	private $variables = array();

	/**
	 * Creates a new public key and a private key pair.
	 *
	 * @param int $strength
	 * @param mixed $passphrase
	 * @param string $keyType
	 * @return void
	 */
	public function __construct($strength = 1024, $passphrase = null, $keyType = 'rsa')
	{
		$config['private_key_bits'] = $strength;
		$config['private_key_type'] = constant('OPENSSL_KEYTYPE_' . strtoupper($keyType));

		$resource = openssl_pkey_new($config);

		// Private key
		openssl_pkey_export($resource, $privateKey);
		if ($passphrase !== null)
			openssl_pkey_export($resource, $privateKeyEncrypted, $passphrase);
		else
			$privateKeyEncrypted = null;

		// Details
		$details = openssl_pkey_get_details($resource);

		// Public key
		$publicKey = $details['key'];

		// Save details
		$this->variables['bits'] = $details['bits'];
		$this->variables[strtolower($keyType)] = $details[strtolower($keyType)];
		$this->variables['publicKey'] = $publicKey;
		$this->variables['privateKey'] = $privateKey;
		$this->variables['privateKeyEncrypted'] = $privateKeyEncrypted;
		$this->variables['resource'] = $resource;
	}

	/**
	 * A getter method for retrieving data.
	 *
	 * @param string $variable
	 * @return mixed
	 */
	public function __get($variable)
	{
		return $this->variables[$variable];
	}
}