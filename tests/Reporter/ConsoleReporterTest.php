<?php

namespace Security\CodeAnalyzer\Tests\Reporter;

use PHPUnit\Framework\TestCase;
use Security\CodeAnalyzer\Reporter\ConsoleReporter;
use Security\CodeAnalyzer\Vulnerability\SQLInjectionVulnerability;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;
use Security\CodeAnalyzer\Vulnerability\XSSVulnerability;

class ConsoleReporterTest extends TestCase
{
    public function testGetName(): void
    {
        $reporter = new ConsoleReporter();
        $this->assertEquals('Console Reporter', $reporter->getName());
    }
    
    public function testGetFormat(): void
    {
        $reporter = new ConsoleReporter();
        $this->assertEquals('text', $reporter->getFormat());
    }
    
    public function testGenerateWithEmptyCollection(): void
    {
        $reporter = new ConsoleReporter();
        $collection = new VulnerabilityCollection();
        
        $report = $reporter->generate($collection);
        
        $this->assertStringContainsString('Security Vulnerability Report', $report);
        $this->assertStringContainsString('Total vulnerabilities found: 0', $report);
    }
    
    public function testGenerateWithVulnerabilities(): void
    {
        $reporter = new ConsoleReporter();
        $collection = new VulnerabilityCollection();
        
        $collection->add(new SQLInjectionVulnerability(
            '/path/to/file1.php',
            10,
            '$query = "SELECT * FROM users WHERE username = \'" . $username . "\'";',
            'high'
        ));
        
        $collection->add(new XSSVulnerability(
            '/path/to/file2.php',
            20,
            'echo $userInput;',
            'medium'
        ));
        
        $report = $reporter->generate($collection);
        
        // Check summary
        $this->assertStringContainsString('Total vulnerabilities found: 2', $report);
        
        // Check severity breakdown
        $this->assertStringContainsString("\033[31mHigh\033[0m: 1", $report);
        $this->assertStringContainsString("\033[33mMedium\033[0m: 1", $report);

        // Check type breakdown
        $this->assertStringContainsString('SQL Injection: 1', $report);
        $this->assertStringContainsString('Cross-Site Scripting (XSS): 1', $report);
        
        // Check detailed vulnerabilities
        $this->assertStringContainsString("\033[1mSQL Injection\033[0m (\033[31mhigh\033[0m)", $report);
        $this->assertStringContainsString('File: /path/to/file1.php', $report);
        $this->assertStringContainsString('Line: 10', $report);
        $this->assertStringContainsString('$query = "SELECT * FROM users WHERE username = \'" . $username . "\'";', $report);
        
        $this->assertStringContainsString("\033[1mCross-Site Scripting (XSS)\033[0m (\033[33mmedium\033[0m)", $report);
        $this->assertStringContainsString('File: /path/to/file2.php', $report);
        $this->assertStringContainsString('Line: 20', $report);
        $this->assertStringContainsString('echo $userInput;', $report);
    }
}