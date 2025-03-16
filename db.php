<?php
$servername = "localhost";
$username = "pi"; // Change to your database username
$password = "t3stpass!"; // Change to your database password
$dbname = "GateKeeper"; // Change to your actual database name

$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
