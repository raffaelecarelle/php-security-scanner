<?php
/**
 * This file contains intentional security vulnerabilities for testing purposes.
 * DO NOT USE THIS CODE IN PRODUCTION!
 */

// SQL Injection vulnerability
function getUserByUsername($username) {
    $db = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    $result = $db->query($query);
    return $result->fetch(PDO::FETCH_ASSOC);
}

// XSS vulnerability
function displayUserInput($userInput) {
    echo "<div>User input: " . $userInput . "</div>";
}

// Command Injection vulnerability
function pingHost($host) {
    $output = [];
    exec("ping -c 4 " . $host, $output);
    return implode("\n", $output);
}

// Usage examples (also vulnerable)
$username = $_GET['username'] ?? '';
$userInput = $_POST['message'] ?? '';
$host = $_GET['host'] ?? 'localhost';

$user = getUserByUsername($username);
displayUserInput($userInput);
$pingResult = pingHost($host);