PHP Security Library
==

This library provides you a handful set of useful helper methods and classes related to security.

## Examples

##### Encrypt data securely.

```php
use \PSL\Encrypter;

$confidentalText = 'I am using PSL';

$cipherText = Encrypter::encrypt(MCRYPT_RIJNDAEL_256, $confidentalText);

// $cipherText is an instance of \PSL\CipherText.
// To extract, do something like this:
$key = $cipherText->key;
$plainText = Encrypter::decrypt($cipherText, $key);

// $plainText is now same as $confidentalText.
```

##### Generate strong random data.

```php
use \PSL\Randomizer;

$data = Randomizer::getRandomBytes(32); // 32 bytes.

$randomFloat = Randomizer::getRandomFloat();
```

Things like [random float generation](https://github.com/kaisellgren/PHP-Security-Library/blob/master/Security/Randomizer.php#L108) is more conplex than what it might seem initially and therefore it's nice to be able to use a library for that.

##### Generate a certificate.

```php
use \PSL\KeyPair;
use \PSL\Certificate;

$keyPair = new KeyPair();

$details = array(
    "countryName" => "FI",
    "stateOrProvinceName" => "Southern Finland",
    "localityName" => "Lahti",
    "organizationName" => "N/A",
    "organizationalUnitName" => "N/A",
    "commonName" => "localhost",
    "emailAddress" => "kaisellgren-at-gmail.com"
);

$certificate = new Certificate($details, $keyPair);

$certificate->sign();

file_put_contents('my.crt', $certificate->export());
```