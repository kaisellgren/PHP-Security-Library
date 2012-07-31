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
 * An interface for calculator classes.
 *
 * @author Kai Sellgren
 * @since 1.00
 */
interface ICalculator
{
	/**
	 * A static method that calculates a value using a specific algorithm for the given data.
	 *
	 * @param mixed $data
	 */
	public function calculate($data);
}