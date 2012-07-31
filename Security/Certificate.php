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
 * This class represents certificates.
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class Security_Certificate
{
	private $csr;
	private $keyPair;
	private $signed = false;

	/**
	 * A constructor for creating a certificate.
	 *
	 * @param array $details
	 * @param Security_KeyPair $keyPair
	 * @return void
	 */
	public function __construct(Array $details, Security_KeyPair $keyPair)
	{
		$this->keyPair = $keyPair;
		$this->csr = openssl_csr_new($details, $keyPair->resource);
	}

	/**
	 * A method for exporting the certificate.
	 *
	 * @param mixed $password
	 * @return string
	 */
	public function export($type = 'x509', $password = null)
	{
		if ($this->signed === false)
		{
			openssl_csr_export($this->csr, $out);
			return $out;
		}
		else
		{
			switch ($type)
			{
				case 'x509':
					openssl_x509_export($this->csr, $out);
					break;
				case 'pkcs12':
					openssl_pkcs12_export($this->csr, $out, $this->keyPair->privateKey, $password);
					break;
			}
			return $out;
		}
	}

	public function readPKCS12($a, $password) {
		openssl_pkcs12_read($a, $c, $password);
		return $c;
	}

	/**
	 * A method for signing the certificate.
	 *
	 * Now it actually becomes a certificate. :)
	 *
	 * @param mixed $CACertificate
	 * @param int $days
	 * @param string $signatureAlgorithm
	 * @param int $serial
	 * @return void
	 */
	public function sign($CACertificate = null, $days = 365, $signatureAlgorithm = 'sha1', $serial = 0)
	{
		$config = array('digest_alg' => ($signatureAlgorithm !== null) ? $signatureAlgorithm : 'sha1');
		$this->csr = openssl_csr_sign($this->csr, $CACertificate, $this->keyPair->resource, $days, $config, $serial);
		$this->signed = true;
	}
}