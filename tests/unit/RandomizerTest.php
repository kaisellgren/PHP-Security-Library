<?php

require_once 'PHPUnit/Framework.php';
require_once 'Security/Randomizer.php';

class RandomizerTest extends PHPUnit_Framework_TestCase
{
	public static $randomData = 'wCTbV7vTzzW0/+jrc84lnj3ghg3GakCUipo2JLmmtFzWzjsM6Zfhxx8WXBsRfhs69V0m/iIATGaYZq62AFngNu2glPJPLbu954ZB+ML3vDyZGvbm2EGL+u1JHM1vSF/2NcK2eGjbbfmtR9fVEoAikiTZg4KanZqzEVKWd0xftWo7SLSUCmZc/j0znh1K4KV821nccN1VDSwl1d496KPALpftAg6ihmGHVNpLthCHYprngzv7jWgpsW/20aBSkfD9+GszF2LkCMjYnJHbv6p6/IMUYOh6nD65WHkOe/fZ9ZIIwmrV9F5mPyAsNADIGtDrgSH2tbiGBsnUbZuHMV6oP3coBvt4H1dRj2csR0m+npc7qHPxAULp7AP7pAwD53yKN+3p+UXbED5y+YbdUcsBF8Z+/g11gTTAFV31yDKnamLJ9mYNyMmRdHUu6sfH7RMSQ5dNczaqsIdpHwy/xWDEixkFMu6ehgAf5uvZsg0QhtPZ+Eh1uNgNkhb7RPVWbXMkcadvEPtZzE4JB8ZbrC+VTlZAJZpk3E2gyqRv5ej/sawZ31QX2uIojq1Zb/zzgPwMk27zwPyX6rVRiVwMZKK/76C583P53gmHPzjxNeMJlEb3h3biBAuqgPJ0gznJ/icAV6pgjfY52WN3yTrHYPGnirFHHk3Z0Msa1kmxhP2kgKGiju4pB9F7N2fJAKUJKmjoJBvaSZnJQyiKCfGoFQrXXamndpRchrKwapeLXkh0E6hcT69rriQT15FfBPw2EDIeV44ydZBXsYUCKs8z3REJ/FhcW9tiqyEiiptHImpxA0LxM+Ey68k+4/MEanPtbu/T3myUQnxZKn7dvH+Ui51A3Mox8Q5+o9GA/Fil9ZpDsTuzjh8coZziyeheoT0EsVyhfxYLSa5yjPSR2a6EMAGX0A3qcAMLneoo5tXaoiO1SoTlmb/XTwowGDpiCVpr60sGyG78gWy9OU+8mHfZ+TJoQRxW34MpyrXAnpNFGIoPCXj0pWezHMOr9UVd8abpN2AWoMR8CeJlpmKAkZ7bzVhlen5aIslKM1UiS4BXaQk3DSQQMtdsQfidvwZITmvXdJShMjkpQiRyJQbewu1ZH/fX6FKAIN/+4INgsD7FMjLW5FWMK55lUHqihnB9u4PnVMMq8o7E/56thsh7USUfUC1MXzbgAynXD0LGjotFRqCspnAVQpAbWjlHzsUyTtgglvuK8LTYcxu/YKDWnbICuOZnO9ZAtHOW7aFNdpW0PGu0wmFmCz999wFvnnYVvJFE+XJhC8whY8ZCQG+Q5piISsLAilOaO+m0XHLhoK/724dwlVNCf2c22x+SRK3f08yBsHiNpN+z2xMYNy63R3HHhW3WAQ==';

	public function testRandomBoolean()
	{
		$boolean = PSL\Randomizer::getRandomBoolean();
		$this->assertTrue(($boolean === true || $boolean === false));
	}

	public function testRandomInteger()
	{
		$integer = PSL\Randomizer::getRandomInteger(-2,-1);
		$this->assertGreaterThanOrEqual(-2, $integer);
		$this->assertLessThanOrEqual(-1, $integer);

		$integer = PSL\Randomizer::getRandomInteger(5, 9);
		$this->assertGreaterThanOrEqual(5, $integer);
		$this->assertLessThanOrEqual(9, $integer);

		$integer = PSL\Randomizer::getRandomInteger(255, 256);
		$this->assertGreaterThanOrEqual(255, $integer);
		$this->assertLessThanOrEqual(256, $integer);

		$integer = PSL\Randomizer::getRandomInteger(-500, 500);
		$this->assertGreaterThanOrEqual(-500, $integer);
		$this->assertLessThanOrEqual(500, $integer);
	}

	public function testRandomToken()
	{
		$token = PSL\Randomizer::getRandomToken(4);
		$this->assertTrue(strlen($token) == 8);
		$this->assertTrue(strlen(preg_replace('#[0123456789abcdef]#i', '', $token)) == 0);
	}

	public function testRandomFloat()
	{
		$float = PSL\Randomizer::getRandomFloat();
		$this->assertType('float', $float);
	}

	public function testRandomGUID()
	{
		$guid = PSL\Randomizer::getRandomGUID();
		$this->assertEquals(1, preg_match('#[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}#', $guid));
	}

	public function testArithmeticMean()
	{
		$randomBytes = base64_decode(self::$randomData);
		$this->assertEquals(0, bccomp((string) PSL\Randomizer::calculateArithmeticMean($randomBytes), '129.198242', 4));
	}

	public function testEntropy()
	{
		$randomBytes = base64_decode(self::$randomData);
		$this->assertEquals(0, bccomp((string) PSL\Randomizer::calculateEntropy($randomBytes), '7.794159', 4));
	}

	public function testMonteCarlo()
	{
		$randomBytes = base64_decode(self::$randomData);
		$this->assertEquals(0, bccomp((string) PSL\Randomizer::calculateMonteCarlo($randomBytes), '3.0117', 4));
	}

	public function testChiSquare()
	{
		$randomBytes = base64_decode(self::$randomData);
		$this->assertEquals(0, bccomp((string) PSL\Randomizer::calculateChiSquare($randomBytes), '8.85', 2));
	}
}
