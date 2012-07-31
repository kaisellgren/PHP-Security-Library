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
 * This class calculates a chi-square distribution for a sequence of bytes.
 *
 * Read on (http://en.wikipedia.org/wiki/Chi-square_distribution) for more details.
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class ChiSquare implements ICalculator
{
	// Pre-calculated values for faster calculations.
	const Z_MAX = 6.0; // The maximum value for the normal z.
	const LOG_SQRT_PI = 0.5723649429247000870717135; // log(sqrt(π))
	const I_SQRT_PI = 0.5641895835477562869480795; // 1/sqrt(π)
	const BIG_X = 20.0; // Max value to represent exp(x)

	/**
	 * Calculates a Chi-square distribution for a sequence of given bytes.
	 * The result is a float representing the probability of how frequently
	 * a truly random sequence of bytes would exceed the calculated value.
	 *
	 * Ideally this float should have a value of 0.5.
	 *
	 * @param mixed $data
	 * @return float
	 */
	public function calculate($data)
	{
		$inputSize = strlen((binary) $data);

		// Holds an array that represents the count of various characters.
		$charCount = array();

		// Loop through the bytes and increase $charCount.
		for ($a = 0; $a < $inputSize; $a++)
		{
			if (isset($charCount[ord($data[$a])]))
				$charCount[ord($data[$a])]++;
			else
				$charCount[ord($data[$a])] = 1;
		}

		// The average number of times a specific character should occur.
		$expectedCount = $inputSize/256;

		$chiSquare = 0;

		for ($i = 0; $i < 256; $i++)
		{
			// Ideally this would be close to 0.
			$a = (isset($charCount[$i]) ? $charCount[$i] : 0) - $expectedCount;

			$chiSquare += ($a * $a) / $expectedCount;
		}

		return $this->calculateChiSquareProbability(round($chiSquare, 2), 255);
	}

	/**
	 * A helper method that returns e^$x as long as $x >= BIG_X.
	 *
	 * @param float $x
	 * @return float
	 */
	private function calculateEx($x)
	{
		return ($x < -self::BIG_X) ? 0.0 : exp($x);
	}

	/**
	 * Calculates the probability for the results of the Chi-square test.
	 *
	 * @param float $x Chi-square value.
	 * @param float $df Degrees of freedom.
	 * @return float
	 */
	private function calculateChiSquareProbability($x, $df)
	{
		if ($x <= 0.0 || $df < 1)
			return 1.0;

		$a = 0.5 * $x;

		if ($df > 1)
			$y = $this->calculateEx(-$a);

		$s = 2.0 * $this->calculateNormalZProbability(-sqrt($x));

		if ($df > 2)
		{
			$x = 0.5 * ($df - 1.0);
			$z = 0.5;

			if ($a > self::BIG_X)
			{
				$e = self::LOG_SQRT_PI;
				$c = log($a);

				while ($z <= $x)
				{
					$e = log($z) + $e;
					$s += $this->calculateEx($c * $z - $a - $e);
					$z += 1.0;
				}

				return ($s);
			}
			else
			{
				$e = self::I_SQRT_PI / sqrt($a);
				$c = 0.0;

				while ($z <= $x)
				{
					$e = $e * ($a / $z);
					$c = $c + $e;
					$z += 1.0;
				}

				return ($c * $y + $s);
			}
		}
		else
			return $s;
	}

	/**
	 * Calculates the probability for the normal z.
	 *
	 * @param float $z
	 * @return float
	 */
	private function calculateNormalZProbability($z)
	{
		if ($z == 0.0)
			$x = 0.0;
		else
		{
			$y = 0.5 * abs($z);

			if ($y >= self::Z_MAX * 0.5)
				$x = 1.0;
			else if ($y < 1.0)
			{
				$w = $y * $y;
				$x = (((((((
				(0.000124818987 * $w -0.001075204047)
								* $w +0.005198775019)
								* $w -0.019198292004)
								* $w +0.059054035642)
								* $w -0.151968751364)
								* $w +0.319152932694)
								* $w -0.531923007300)
								* $w +0.797884560593)
								* $y * 2.0;
			}
			else
			{
				$y -= 2.0;
				$x = (((((((((((((
				-0.000045255659 * $y +0.000152529290)
								* $y -0.000019538132)
								* $y -0.000676904986)
								* $y +0.001390604284)
								* $y -0.000794620820)
								* $y -0.002034254874)
								* $y +0.006549791214)
								* $y -0.010557625006)
								* $y +0.011630447319)
								* $y -0.009279453341)
								* $y +0.005353579108)
								* $y -0.002141268741)
								* $y +0.000535310849)
								* $y +0.999936657524;
			}
		}

		return $z > 0.0 ? ($x + 1.0) * 0.5 : (1.0 - $x) * 0.5;
	}
}