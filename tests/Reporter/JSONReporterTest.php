<?php

namespace Security\CodeAnalyzer\Tests\Reporter;

use PHPUnit\Framework\TestCase;
use Security\CodeAnalyzer\Reporter\JSONReporter;
use Security\CodeAnalyzer\Vulnerability\SQLInjectionVulnerability;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;
use Security\CodeAnalyzer\Vulnerability\XSSVulnerability;

class JSONReporterTest extends TestCase
{
    public function testGetName(): void
    {
        $reporter = new JSONReporter();
        $this->assertEquals('JSON Reporter', $reporter->getName());
    }
    
    public function testGetFormat(): void
    {
        $reporter = new JSONReporter();
        $this->assertEquals('json', $reporter->getFormat());
    }
    
    public function testGenerateWithEmptyCollection(): void
    {
        $reporter = new JSONReporter();
        $collection = new VulnerabilityCollection();
        
        $report = $reporter->generate($collection);
        
        // Decode the JSON report
        $data = json_decode($report, true);
        
        // Check structure
        $this->assertIsArray($data);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('vulnerabilities', $data);
        
        // Check summary
        $this->assertEquals(0, $data['summary']['total']);
        $this->assertCount(0, $data['vulnerabilities']);
    }
    
    public function testGenerateWithVulnerabilities(): void
    {
        $reporter = new JSONReporter();
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
        
        // Decode the JSON report
        $data = json_decode($report, true);
        
        // Check structure
        $this->assertIsArray($data);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('vulnerabilities', $data);
        
        // Check summary
        $this->assertEquals(2, $data['summary']['total']);
        $this->assertEquals(1, $data['summary']['by_severity']['high']);
        $this->assertEquals(1, $data['summary']['by_severity']['medium']);
        $this->assertEquals(1, $data['summary']['by_type']['SQL Injection']);
        $this->assertEquals(1, $data['summary']['by_type']['Cross-Site Scripting (XSS)']);
        
        // Check vulnerabilities
        $this->assertCount(2, $data['vulnerabilities']);
        
        // Check first vulnerability
        $this->assertEquals('SQL Injection', $data['vulnerabilities'][0]['type']);
        $this->assertEquals('high', $data['vulnerabilities'][0]['severity']);
        $this->assertEquals('/path/to/file1.php', $data['vulnerabilities'][0]['file']);
        $this->assertEquals(10, $data['vulnerabilities'][0]['line']);
        $this->assertEquals('$query = "SELECT * FROM users WHERE username = \'" . $username . "\'";', $data['vulnerabilities'][0]['code']);
        
        // Check second vulnerability
        $this->assertEquals('Cross-Site Scripting (XSS)', $data['vulnerabilities'][1]['type']);
        $this->assertEquals('medium', $data['vulnerabilities'][1]['severity']);
        $this->assertEquals('/path/to/file2.php', $data['vulnerabilities'][1]['file']);
        $this->assertEquals(20, $data['vulnerabilities'][1]['line']);
        $this->assertEquals('echo $userInput;', $data['vulnerabilities'][1]['code']);
    }
}