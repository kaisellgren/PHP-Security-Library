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
 * This class is used for executing commands in a secure manner.
 * Some method names of this class are against the coding standards of this project.
 * I wanted to keep the method naming similar to native PHP to make people feel more comfortable.
 *
 * @author Kai Sellgren
 * @since 1.00
 */
class Executor
{
	/**
	 * Executes a command securely.
	 *
	 * @param string $command
	 * @param array $arguments An array of arguments.
	 * @param array $output An optional array to be filled with the lines of the output.
	 * @param mixed $return An optional variable to be filled with the return value.
	 */
	public static function exec($command, $arguments = array(), &$output = null, &$return = null)
	{
		return exec(self::buildCommand($command, $arguments), $output, $return);
	}

	/**
	 * Executes a command securely and displays the raw output.
	 *
	 * @param string $command
	 * @param array $arguments An array of arguments.
	 * @param mixed $return An optional variable to be filled with the return value.
	 */
	public static function passthru($command, $arguments = array(), &$return = null)
	{
		passthru(self::buildCommand($command, $arguments), $return);
	}

	/**
	 * Executes a command securely and returns the raw output as binary.
	 *
	 * @param string $command
	 * @param array $arguments An array of arguments.
	 * @return binary
	 */
	public static function shell_exec($command, $arguments = array())
	{
		return shell_exec(self::buildCommand($command, $arguments));
	}

	/**
	 * Executes a command securely and displays the output.
	 *
	 * @param string $command
	 * @param array $arguments An array of arguments.
	 * @param mixed $return An optional variable to be filled with the return value.
	 */
	public static function system($command, $arguments = array(), &$return = null)
	{
		system(self::buildCommand($command, $arguments), $return);
	}

	/**
	 * Builds a command securely.
	 *
	 * @param string $command
	 * @param array $arguments
	 * @return string
	 */
	private static function buildCommand($command, $arguments)
	{
		$arguments = (array) $arguments;

		// Builds the command.
		foreach ($arguments as $argument)
			$command .= " " . escapeshellarg($argument);

		return $command;
	}
}