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
 * The CipherText is used for "storing" data for encryption purposes.
 *
 * @author Kai Sellgren
 * @since 1.00
 *
 * @property binary $cipherText The cipher text in binary format.
 * @property binary $iv The initialization vector.
 * @property string $operationMode The operation mode.
 * @property string $cipher The cipher algorithm.
 */
class CipherText
{
	private $variables;

	/**
	 * You can construct a new CipherText object two ways -- If you pass a JSON encoded string into the first parameter,
	 * its contents will be loaded into the object, and if not, the given parameters are used.
	 *
	 * @param binary $cipherText
	 * @param mixed $plainText
	 * @param string $cipher
	 * @param string $operationMode
	 * @param binary $iv
	 * @return void
	 */
	public function __construct($cipherText = null, $plainText = null, $cipher = null, $operationMode = null, $iv = null)
	{
		// It's a JSON encoded string.
		if (func_num_args() === 1)
		{
			$array = json_decode($properties);

			// If it was encoded using base64, then decode it back.
			if ($array['encoding'] === 'base64')
			{
				$this->variables['cipherText'] = base64_decode($array['cipherText']);
				$this->variables['iv'] = base64_decode($array['iv']);
			}
			else
			{
				$this->variables['cipherText'] = $array['cipherText'];
				$this->variables['iv'] = $array['iv'];
			}

			// These should never be encoded as they are simple strings.
			$this->variables['blockMode'] = $array['blockMode'];
			$this->variables['cipher'] = $array['cipher'];
		}
		else
		{
			// Set variables directly.
			$this->variables['cipherText'] = $cipherText;
			$this->variables['iv'] = $iv;
			$this->variables['blockMode'] = $operationMode;
			$this->variables['cipher'] = $cipher;
		}
	}

	/**
	 * A getter for returning properties.
	 *
	 * @param string $property
	 * @return mixed
	 */
	public function __get($property)
	{
		return $this->variables[$property];
	}

	/**
	 * A setter for setting properties.
	 *
	 * @param string $property
	 * @param mixed $value
	 * @return void
	 */
	public function __set($property, $value)
	{
		$this->variables[$property] = $value;
	}

	/**
	 * This method will save the contents of this object into a string and can then be saved to a file/database.
	 *
	 * @return string
	 */
	public function save()
	{
		$details = array(
			'cipherText' => base64_encode($this->variables['cipherText']),
			'iv' => base64_encode($this->variables['iv']),
			'blockMode' => $this->variables['blockMode'],
			'cipher' => $this->variables['cipher'],
			'encoding' => 'base64'
		);

		// JSON provides good portability and it seems to be safer to use than serialize().
		return json_encode($details);
	}

	/**
	 * Returns the CipherText object details. Useful for saving it to a file/database.
	 *
	 * @return string
	 */
	public function __toString()
	{
		return $this->save();
	}
}