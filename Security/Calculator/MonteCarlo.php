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
 * This class approximates the value of π using a Monte Carlo method.
 *
 * Read on (http://en.wikipedia.org/wiki/Monte_Carlo_method) for more details.
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class MonteCarlo implements ICalculator
{
	/**
	 * The length of the byte sequence (in N bytes) used in cordinate calculations.
	 * We use a value of 6 here, because PHP uses IEEE double precision floating-point format
	 * with a significand precision of 52-bits.
	 *
	 * @var int
	 */
	const MONTE_N = 6;

	/**
	 * Approximates the value of π using a Monte Carlo method with the given input data. A value of π is ideal.
	 *
	 * @param mixed $input
	 * @return float
	 */
	public function calculate($input)
	{
		$inputSize = strlen((binary) $input);

		// This method shouldn't be used for that less data.
		if ($inputSize < 6)
			return 4.0;

		// In-circle distance.
		$inCirc = pow(pow(256.0, self::MONTE_N / 2) - 1, 2.0);

		// A counter used to determine the sequence size.
		$seqCounter = 0;

		// How many times did we end up testing a byte sequence.
		$sequences = 0;

		// How many times did we hit?
		$hits = 0;

		// Holds the data for calculations.
		$data = '';

		// Loop through all bytes.
		for ($i = 0; $i < $inputSize; $i++)
		{
			$seqCounter++;

			// Add the byte in the current position $i to the dataset.
			// We are constructing a set of self::monten bytes.
			$data .= substr((binary) $input, $i, 1);

			// For every successive set of 6 bytes, we use 24-bits for the X-cordinates and 24-bits for the Y-cordinates.
			if ($seqCounter >= self::MONTE_N)
			{
				$montex = $montey = 0;
				$seqCounter = 0;
				$sequences++;

				// Calculate $montex and $montey.
				for ($j = 0; $j < self::MONTE_N / 2; $j++)
				{
					// $montex is the first 24-bits.
					$montex = ($montex * 256.0) + ord($data[$j]);

					// $montey is the following 24-bits.
					$montey = ($montey * 256.0) + ord($data[(self::MONTE_N / 2) + $j]);
				}

				// x^2 + y^2 <= $inCirc
				if (($montex * $montex + $montey * $montey) <= $inCirc)
					$hits++;

				$data = '';
			}
		}

		// The calculated PI.
		$montePi = 4.0 * ($hits / $sequences);

		return $montePi;
	}
}