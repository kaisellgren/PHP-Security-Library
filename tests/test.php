<?php


// Register an autoload function.
spl_autoload_register(function ($class) {
	$class = str_replace('PSL', 'Security', $class);
	require('../' . $class . '.php');
});

function asd()
{
    basd();
}

function basd()
{
    asdasd();
}

function asdasd()
{
    
}

asd();

$st = microtime(true);
for ($a = 0; $a < 1; $a++)
	hash_hmac('sha256', 'asdasd asd asda sds ', 'asdasd asd asda sds ', true);
echo "Took: " . (microtime(true) - $st);

exit;
/*$a = new mysqli('localhost', 'root', 'hottis');
var_dump($a instanceof mysqli);

$a = new PDO('mysql:host=localhost', 'root', 'hottis');
var_dump($a instanceof PDO);

$a = mysql_connect('localhost', 'root', 'hottis');
var_dump(get_resource_type($a) === 'mysql link');

$a = new SQLite3('asd.db');
var_dump($a instanceof SQLite3);*/

// Others? oci8, pg_connect, ibm_db2, php_interbase

// Configuration (entirely optional).
$config = array(
	// Custom table names.
	'tableUser' => 'Member',

	// Database instance (PDO) to reuse.
	'class' => Yii::app()->db->pdoInstance
);

$rbac = new \PSL\RBAC($config);

$rbac->createRole('admin');
$rbac->createTask('post');

$rbac->createPermission('deletePost', 'Can delete any posts.');
$rbac->createPermission('updatePost', 'Can update any posts.');

$rbac->addTaskChild(array('deletePost', 'updatePost'));

$rbac->addRoleTask(array('post'));

$rbac->assignRole(16, 'admin');





/* YII EXAMPLE ACTION */
function actionRegisterUser()
{
	$user = new User();
	$user->firstName = 'example';

	if ($user->save())
	{
		Yii::app()->rbac->assignRole($user->id, 'authenticated');
	}
}


exit;
define('PSL_RANDOM_GENERATOR', 'capicom');
var_dump(PSL\Randomizer::getRandomBytes(1), PSL\Randomizer::$generatorUsed);

exit;
$availableCiphers = PSL\Encrypter::getSupportedCiphers();
$availableModes = PSL\Encrypter::getSupportedModes();

$enc = new PSL\Encrypter();

$key = 'asdfgha test key';
$plainText = 'some plain text';

foreach ($availableCiphers as $cipher)
{
	foreach ($availableModes as $mode)
	{
		try
		{
			$cipherText = $enc->encrypt($cipher, $plainText, $key, $mode);
			if ($cipherText != false)
			{
				$plainTextDeciphered = $enc->decrypt($cipherText, $key);
			}
		}
		catch (Exception $e)
		{
			echo "<br />" . $e->getMessage() . "<br />";
		}

		echo "$cipher ($mode): $cipherText<br />";

		flush();
	}
}

exit;
/*
header('content-type: text/plain');

$userInput = 'ab\\a'; // The user tries to traverse

//Security_Executor::shell('RENAME', 'C:\\' . $userInput, 'target');// and succeeds lol

exit;
echo '<pre>';

function __autoload($class)
{
	require('../' . str_replace('_', '/', $class) . '.php');
}

$keyPair = new Security_KeyPair();

$details = array(
"countryName" => "UK",
"stateOrProvinceName" => "Southern Finland",
"localityName" => "Lahti",
"organizationName" => "N/A",
"organizationalUnitName" => "N/A",
"commonName" => "localhost",
"emailAddress" => "kaisellgren@gmail.com"
);

$certificate = new Security_Certificate($details, $keyPair);

$certificate->sign();

file_put_contents('my.crt', $certificate->export());

// ENCRYPT KEY DSA & DH check? use pkcs #7 export?

*/