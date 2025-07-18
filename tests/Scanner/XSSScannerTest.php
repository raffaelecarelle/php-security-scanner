<?php

namespace Security\CodeAnalyzer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use Security\CodeAnalyzer\Scanner\XSSScanner;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;
use Security\CodeAnalyzer\Vulnerability\XSSVulnerability;

class XSSScannerTest extends TestCase
{
    private XSSScanner $scanner;
    
    protected function setUp(): void
    {
        $this->scanner = new XSSScanner();
    }
    
    public function testGetName(): void
    {
        $this->assertEquals('XSS Scanner', $this->scanner->getName());
    }
    
    public function testGetDescription(): void
    {
        $this->assertEquals(
            'Scans for Cross-Site Scripting (XSS) vulnerabilities in output functions',
            $this->scanner->getDescription()
        );
    }
    
    public function testScanWithNoVulnerabilities(): void
    {
        $code = <<<'CODE'
<?php
function displaySafeUserInput($userInput) {
    echo "<div>User input: " . htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8') . "</div>";
}

function displaySafeUserInput2($userInput) {
    $safeInput = strip_tags($userInput);
    echo "<div>User input: " . $safeInput . "</div>";
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'safe_file.php');
        var_dump($vulnerabilities->getAll());
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertEquals(0, count($vulnerabilities));
    }
    
    public function testScanWithXSSVulnerability(): void
    {
        $code = <<<'CODE'
<?php
function displayUserInput($userInput) {
    echo "<div>User input: " . $userInput . "</div>";
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'vulnerable_file.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertEquals(1, count($vulnerabilities));
        
        $vulnerability = $vulnerabilities->current();
        $this->assertInstanceOf(XSSVulnerability::class, $vulnerability);
        $this->assertEquals('vulnerable_file.php', $vulnerability->getFilePath());
        $this->assertEquals('medium', $vulnerability->getSeverity());
    }
    
    public function testScanWithMultipleVulnerabilities(): void
    {
        $code = <<<'CODE'
<?php
function displayUserInput($userInput) {
    echo "<div>User input: " . $userInput . "</div>";
}

function displayUserProfile($username, $bio) {
    echo "<h1>" . $username . "</h1>";
    echo "<p>" . $bio . "</p>";
}

function displaySafeUserInput($userInput) {
    echo "<div>User input: " . htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8') . "</div>";
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'multiple_vulnerabilities.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertEquals(3, count($vulnerabilities));
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
            if ($vulnerability instanceof XSSVulnerability) {
                $found = true;
                $this->assertEquals($fixtureFile, $vulnerability->getFilePath());
                $this->assertEquals('medium', $vulnerability->getSeverity());
                // Check that the vulnerability contains the vulnerable code
                $this->assertStringContainsString('echo "<div>User input: " . $userInput . "</div>"', $vulnerability->getCodeSnippet());
            }
        }
        
        $this->assertTrue($found, 'XSS vulnerability not found in fixture file');
    }
    
    public function testScanWithPrintStatement(): void
    {
        $code = <<<'CODE'
<?php
function displayUserInput($userInput) {
    print "<div>User input: " . $userInput . "</div>";
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'print_statement.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertGreaterThan(0, count($vulnerabilities));
    }
    
    public function testScanWithIncludeStatement(): void
    {
        $code = <<<'CODE'
<?php
function loadTemplate($templateName) {
    include $templateName;
}
CODE;
        
        $vulnerabilities = $this->scanner->scan($code, 'include_statement.php');
        
        $this->assertInstanceOf(VulnerabilityCollection::class, $vulnerabilities);
        $this->assertGreaterThan(0, count($vulnerabilities));
    }
}