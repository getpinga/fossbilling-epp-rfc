<?php
require_once "Tembo.php";

use Pinga\Tembo\Epp;
$config = include "config.php";
$c = $config["db"];

$registrar = "Epp";

try
{
    // Establish the PDO connection
    $dsn = $c["type"] . ":host=" . $c["host"] . ";port=" . $c["port"] . ";dbname=" . $c["name"];
    $pdo = new PDO($dsn, $c["user"], $c["password"]);

    // Use a prepared statement to prevent SQL injection
    $stmt = $pdo->prepare("SELECT * FROM tld_registrar WHERE registrar = :registrar");

    // Bind the $registrar value to the :registrar parameter
    $stmt->bindValue(":registrar", $registrar);

    // Execute the prepared statement
    $stmt->execute();

    // Fetch all rows from the result set
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $config = [];

    foreach ($rows as $row)
    {
        // Decode the JSON string into an array
        $config = json_decode($row["config"], true);
		
        // Extract id
        $registrar_id = $row["id"];
    }

    if (empty($config))
    {
        throw new Exception("Database cannot be accessed right now.");
    }

}
catch(PDOException $e)
{
    echo "Database error: " . $e->getMessage();
}
catch(Exception $e)
{
    echo "General error: " . $e->getMessage();
}

function connectEpp(string $registry, $config)
{
    try
    {
        $epp = new Epp();
        $info = [
        //For EPP-over-HTTPS,  'host' => 'https://registry.example.com/epp',
        "host" => $config["host"],
        //For EPP-over-HTTPS , port is usually 443
        "port" => $config["port"], "timeout" => 30, "tls" => "1.3", "bind" => false, "bindip" => "1.2.3.4:0", "verify_peer" => false, "verify_peer_name" => false,
        //For EPP-over-HTTPS , change false to 2
        "verify_host" => false, "cafile" => "", "local_cert" => $config["ssl_cert"], "local_pk" => $config["ssl_key"], "passphrase" => "", "allow_self_signed" => true, ];
        $epp->connect($info);
        $login = $epp->login(["clID" => $config["username"], "pw" => $config["password"],
        //'newpw' => 'testpassword2',
        "prefix" => "tembo", ]);
        if (array_key_exists("error", $login))
        {
            echo "Login Error: " . $login["error"] . PHP_EOL;
            exit();
        }
        else
        {
            echo "Login Result: " . $login["code"] . ": " . $login["msg"][0] . PHP_EOL;
        }
        return $epp;
    }
    catch(EppException $e)
    {
        return "Error : " . $e->getMessage();
    }
}

try {
    // Fetch all domains
    $stmt = $pdo->prepare('SELECT sld, tld FROM service_domain WHERE tld_registrar_id = :registrar');
    $stmt->bindValue(':registrar', $registrar_id);
    $stmt->execute();
    $domains = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $epp = connectEpp("generic", $config);

    foreach ($domains as $domainRow) {
        // Combine sld and tld into a single domain name
        $domain = $domainRow['sld'] . $domainRow['tld'];

        $params = ["domainname" => $domain];
        $domainInfo = $epp->domainInfo($params);

        if (array_key_exists("error", $domainInfo)) {
            echo "DomainInfo Error: " . $domainInfo["error"] . " (" . $domain . ")" . PHP_EOL;
            continue;
        }
        
        $ns = $domainInfo['ns'];

        $ns1 = isset($ns[1]) ? $ns[1] : null;
        $ns2 = isset($ns[2]) ? $ns[2] : null;
        $ns3 = isset($ns[3]) ? $ns[3] : null;
        $ns4 = isset($ns[4]) ? $ns[4] : null;
		
		$exDate = $domainInfo['exDate'];
		$datetime = new DateTime($exDate);
		$formattedExDate = $datetime->format('Y-m-d H:i:s');
		
		$statuses = $domainInfo['status'];

		$clientStatuses = ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'];
		$serverStatuses = ['serverDeleteProhibited', 'serverTransferProhibited', 'serverUpdateProhibited'];

		// Check if all client statuses are present in the $statuses array
		$clientProhibited = count(array_intersect($clientStatuses, $statuses)) === count($clientStatuses);

		// Check if all server statuses are present in the $statuses array
		$serverProhibited = count(array_intersect($serverStatuses, $statuses)) === count($serverStatuses);

		if ($clientProhibited || $serverProhibited) {
 		   $locked = 1;
		} else {
 		   $locked = 0;
		}

		// Prepare the UPDATE statement
		$stmt = $pdo->prepare('UPDATE service_domain SET ns1 = :ns1, ns2 = :ns2, ns3 = :ns3, ns4 = :ns4, expires_at = :expires_at, locked = :locked, transfer_code = :transfer_code WHERE sld = :sld AND tld = :tld');

		// Bind the values to the statement
		$stmt->bindValue(':ns1', $ns1);
		$stmt->bindValue(':ns2', $ns2);
		$stmt->bindValue(':ns3', $ns3);
		$stmt->bindValue(':ns4', $ns4);
		$stmt->bindValue(':expires_at', $formattedExDate);
		$stmt->bindValue(':locked', $locked);
        $stmt->bindValue(':transfer_code', $domainInfo["authInfo"]);
		$stmt->bindValue(':sld', $domainRow['sld']);
		$stmt->bindValue(':tld', $domainRow['tld']);

        // Execute the statement
        $stmt->execute();
        
        echo "Update successful for domain: " . $domain . PHP_EOL;
    }

    $logout = $epp->logout();
    echo "Logout Result: " . $logout["code"] . ": " . $logout["msg"][0] . PHP_EOL;
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage();
} catch(EppException $e) {
    echo "Error: ", $e->getMessage();
}
