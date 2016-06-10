<html>
<body>
	<?php

	//DBCONN
	try {
		$db = new PDO('mysql:host=databases.aii.avans.nl;dbname=bsijs1_db', 'bsijs1', 'Ab12345');
	} catch(PDOException $ex) {
		echo 'error';
	}	

	//Encrypt
	$key = pack('H*', "bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3");
	$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);

	$currentId = -1;
	$msgLine = "";	
	
	function login($username, $password) {
		global $currentId;
		global $db;
		
		$stmt = $db->prepare("SELECT * FROM bsijs1_db.secuirity2 WHERE username = :user AND password = :pass");
		$stmt->bindParam(':user', $username);
		$stmt->bindParam(':pass', $password);
		$stmt->execute();

		if ($stmt->rowCount() > 0) {
			$currentId = $stmt->fetch()['user_id'];
			return true;
		}
		return false;
	}

	function encrypt($message) {
		global $key;
		global $iv;

		$encryptedMessage = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $message, MCRYPT_MODE_CBC, $iv);
		$encryptedMessage  = $iv . $encryptedMessage;
		$message_base64 = base64_encode($encryptedMessage);
		
		return $message_base64;
	}

	function decrypt($message) {
		global $iv_size;
		global $key;

		$enc_message = $message;
		$enc_message_dec = base64_decode($enc_message);
		$iv_dec = substr($enc_message_dec, 0, $iv_size);

		$message_dec = substr($enc_message_dec, $iv_size);
		$message = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $message_dec, MCRYPT_MODE_CBC, $iv_dec);
		mcrypt_de

		return $message;
	}

	function insertMessage($message) {
		global $currentId;
		global $db;
		$stmtInsert = $db->prepare("UPDATE bsijs1_db.secuirity2 SET message = :message WHERE secuirity2.user_id = :user_id");
		$stmtInsert->bindParam(':user_id', $currentId);
		$stmtInsert->bindParam(':message', $message);
		$stmtInsert->execute();
		var_dump($stmtInsert->execute());
	}

	function insertUser($username, $password) {
		global $currentId;
		global $db;
		$stmtInsertUser = $db->prepare("INSERT INTO bsijs1_db.secuirity2 (username, password) VALUES (:username, :password)");
		$stmtInsertUser->bindParam(':username', $username);
		$stmtInsertUser->bindParam(':password', $password);
		$stmtInsertUser->execute();
		$currentId = $db->lastInsertId();
		var_dump($db->lastInsertId());
	}

	function setMsgLine() {
		global $db;
		global $msgLine;
		global $currentId;
		$stmt2 = $db->prepare("SELECT message FROM bsijs1_db.secuirity2 WHERE user_id = :id");
		$stmt2->bindParam(':id', $currentId);
		$stmt2->execute();		
		if($stmt2->rowCount() > 0) {
			$msgLine = "";
			$msgCount = 0;
			$row = $stmt2->fetch();
			$message = decrypt($row['message']);
			$msgLine .= trim($message);
		}
	}

	if (isset($_POST['message']) && strlen($_POST['message']) > 0
		&& isset($_POST['username']) && $_POST['username'] !== ''
		&& isset($_POST['password']) && $_POST['password'] !== '') {

		$encryptedMessage = encrypt($_POST['message']);

	if (login($_POST['username'], $_POST['password']) === false) {
		insertUser($_POST['username'], $_POST['password']);
	}

	insertMessage($encryptedMessage);


} else if(isset($_POST['username']) && $_POST['username'] !== ''
	&& isset($_POST['password']) && $_POST['password'] !== '') {
		if (login($_POST['username'], $_POST['password']) === true) {
			setMsgLine();
		}

}
$db = NULL;
?>
	<h2>Encrypt R Us!</h2>
	<form method="POST">
		<label for="username">Gebruikersnaam: </label>
		<input type="text" name="username" id="username"/></br>
		<label for="password">Wachtwoord: </label>
		<input type="text" name="password" id="password"/></br>
		<label for="message">Geheim bericht: </label>
		<textarea id="message" name="message"><?php if ($msgLine && strlen($msgLine) > 0) echo $msgLine; ?></textarea></br>
		<button type="submit">Verstuur!</button>
	</form>

</body>
</html>