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

namespace PSL\Calculator;

/**
 * This class calculates entropy for any given input data.
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class Entropy implements ICalculator
{
	/**
	 * Holds the data to use in calculations.
	 *
	 * @var binary
	 */
	private $data;

	/**
	 * Calculates the amount of entropy in bits per byte in the given data.
	 * A value of 8-bits per byte is ideal and hints for equal distribution of information.
	 *
	 * @param mixed $data
	 * @return float
	 */
	public function calculate($data)
	{
		$this->data = (binary) $data;
		unset($data); // Free up memory.

		// Event count.
		$eventCount = strlen($this->data);

		// Calculate entropy frequencies.
		$tokenFrequencies = $this->calculateEntropyFrequencies($eventCount);

		// Loop through all frequencies.
		$entropy = 0;
		$tokenProbabilities = array();
		foreach ($tokenFrequencies as $token => $frequency)
		{
			// Calculate probability for the token.
			$tokenProbabilities[$token] = $frequency / $eventCount;

			// Ideally this token should add -0.03125-bits of entropy to the set.
			$entropy += $tokenProbabilities[$token] * log($tokenProbabilities[$token], 2);
		}

		// Free up memory.
		$this->data = null;

		return -$entropy;
	}

	/**
	 * A private method for returning a byte of a certain position.
	 *
	 * @param int $x
	 * @return binary
	 */
	private function getByte($x)
	{
		return substr($this->data, $x, 1);
	}

	/**
	 * A private method for calculating frequencies.
	 *
	 * @param int $eventCount
	 * @return void
	 */
	private function calculateEntropyFrequencies($eventCount)
	{
		$tokenFrequencies = array();

		// Loop through all events (bytes).
		for ($i = 0; $i < $eventCount; $i++)
		{
			// Retrieve the value.
			$token = ord($this->getByte($i));

			// Increase the frequency counter for the token.
			if (isset($tokenFrequencies[$token]))
				$tokenFrequencies[$token]++;
			else
				$tokenFrequencies[$token] = 1;
		}

		return $tokenFrequencies;
	}
}