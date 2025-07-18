<?php

namespace Security\CodeAnalyzer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use Security\CodeAnalyzer\Scanner\SQLInjectionScanner;
use Security\CodeAnalyzer\Vulnerability\SQLInjectionVulnerability;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

class SQLInjectionScannerTest extends TestCase
{
    private SQLInjectionScanner $scanner;
    
    protected function setUp(): void
    {
        $this->scanner = new SQLInjectionScanner();
    }
    
    public function testGetName(): void
    {
        $this->assertEquals('SQL Injection Scanner', $this->scanner->getName());
    }
    
    public function testGetDescription(): void
    {
        $this->assertEquals(
            'Scans for SQL injection vulnerabilities in database queries',
            $this->scanner->getDescription()
        );
    }
    
    public function testScanWithNoVulnerabilities(): void
    {
        $code = <<<'CODE'
<?php
function safeQuery($userId) {
    $db = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'safe_file.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertEquals(0, count($vulnerabilities));
    }
    
    public function testScanWithSQLInjectionVulnerability(): void
    {
        $code = <<<'CODE'
<?php
function getUserByUsername($username) {
    $db = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    $result = $db->query($query);
    return $result->fetch(PDO::FETCH_ASSOC);
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'vulnerable_file.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertEquals(1, count($vulnerabilities));
        
        $vulnerability = $vulnerabilities->current();
        $this->assertInstanceOf(SQLInjectionVulnerability::class, $vulnerability);
        $this->assertEquals('vulnerable_file.php', $vulnerability->getFilePath());
        $this->assertEquals('high', $vulnerability->getSeverity());
    }
    
    public function testScanWithMultipleVulnerabilities(): void
    {
        $code = <<<'CODE'
<?php
function getUserByUsername($username) {
    $db = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    $result = $db->query($query);
    return $result->fetch(PDO::FETCH_ASSOC);
}

function getUserByEmail($email) {
    $mysqli = new mysqli('localhost', 'user', 'password', 'test');
    $result = $mysqli->query("SELECT * FROM users WHERE email = '" . $email . "'");
    return $result->fetch_assoc();
}

function searchUsers($term) {
    $db = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');
    // This is safe
    $stmt = $db->prepare("SELECT * FROM users WHERE username LIKE ?");
    $stmt->execute(["%$term%"]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'multiple_vulnerabilities.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertEquals(2, count($vulnerabilities));
    }
    
    public function testScanWithFixtureFile(): void
    {
        $fixtureFile = __DIR__ . '/../fixtures/vulnerable.php';
        $code = file_get_contents($fixtureFile);
        
        $vulnerabilities = $this->scanner->scan($code, $fixtureFile);
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertGreaterThan(0, count($vulnerabilities));
        
        $found = false;
        foreach ($vulnerabilities as $vulnerability) {
            if ($vulnerability instanceof SQLInjectionVulnerability) {
                $found = true;
                $this->assertEquals($fixtureFile, $vulnerability->getFilePath());
                $this->assertEquals('high', $vulnerability->getSeverity());
                // Check that the vulnerability contains the vulnerable code
                $this->assertStringContainsString('$query = "SELECT * FROM users WHERE username', $vulnerability->getCodeSnippet());
            }
        }
        
        $this->assertTrue($found, 'SQL Injection vulnerability not found in fixture file');
    }
    
    public function testScanWithMySQLiFunctions(): void
    {
        $code = <<<'CODE'
<?php
function getUserByUsername($username) {
    $mysqli = new mysqli('localhost', 'user', 'password', 'test');
    $result = mysqli_query($mysqli, "SELECT * FROM users WHERE username = '" . $username . "'");
    return mysqli_fetch_assoc($result);
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'mysqli_functions.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertGreaterThan(0, count($vulnerabilities));
    }
}