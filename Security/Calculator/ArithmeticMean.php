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
 * This class calculates arithmetic mean values for any given input data.
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class ArithmeticMean implements ICalculator
{
	/**
	 * Calculates the arithmetic mean for the given data. A value of 127.5 is ideal.
	 *
	 * @param mixed $data
	 * @return float
	 */
	public function calculate($data)
	{
		$value = 0;

		// Loop through all the bytes and sum them up.
		for ($a = 0, $length = strlen((binary) $data); $a < $length; $a++)
			$value += ord($data[$a]);

		// The average should be 127.5.
		return (float) $value/$length;
	}
}