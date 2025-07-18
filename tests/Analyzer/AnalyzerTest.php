<?php

namespace Security\CodeAnalyzer\Tests\Analyzer;

use PHPUnit\Framework\TestCase;
use Security\CodeAnalyzer\Analyzer\Analyzer;
use Security\CodeAnalyzer\Scanner\ScannerInterface;
use Security\CodeAnalyzer\Vulnerability\SQLInjectionVulnerability;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

class AnalyzerTest extends TestCase
{
    public function testAddScanner(): void
    {
        $analyzer = new Analyzer();
        $scanner = $this->createMock(ScannerInterface::class);
        
        $analyzer->addScanner($scanner);
        
        $this->assertCount(1, $analyzer->getScanners());
        $this->assertSame($scanner, $analyzer->getScanners()[0]);
    }
    
    public function testGetScanners(): void
    {
        $analyzer = new Analyzer();
        $this->assertCount(0, $analyzer->getScanners());
        
        $scanner1 = $this->createMock(ScannerInterface::class);
        $scanner2 = $this->createMock(ScannerInterface::class);
        
        $analyzer->addScanner($scanner1);
        $analyzer->addScanner($scanner2);
        
        $scanners = $analyzer->getScanners();
        $this->assertCount(2, $scanners);
        $this->assertSame($scanner1, $scanners[0]);
        $this->assertSame($scanner2, $scanners[1]);
    }
    
    public function testAnalyzeFile(): void
    {
        // Create a temporary test file
        $tempFile = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tempFile, '<?php $query = "SELECT * FROM users WHERE id = " . $_GET["id"]; ?>');
        
        // Create a mock scanner that returns a vulnerability
        $scanner = $this->createMock(ScannerInterface::class);
        $vulnerability = new SQLInjectionVulnerability($tempFile, 1, '$query = "SELECT * FROM users WHERE id = " . $_GET["id"];', 'high');
        $vulnerabilityCollection = new VulnerabilityCollection();
        $vulnerabilityCollection->add($vulnerability);
        
        $scanner->expects($this->once())
            ->method('scan')
            ->with(
                $this->stringContains('<?php'),
                $this->equalTo($tempFile)
            )
            ->willReturn($vulnerabilityCollection);
        
        // Create the analyzer and add the scanner
        $analyzer = new Analyzer();
        $analyzer->addScanner($scanner);
        
        // Analyze the file
        $result = $analyzer->analyzeFile($tempFile);
        
        // Check the result
        $this->assertCount(1, $result);
        $this->assertSame($vulnerability, $result->getAll()[0]);
        
        // Clean up
        unlink($tempFile);
    }
    
    public function testAnalyzeFileWithMultipleScanners(): void
    {
        // Create a temporary test file
        $tempFile = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tempFile, '<?php $query = "SELECT * FROM users WHERE id = " . $_GET["id"]; ?>');
        
        // Create mock scanners
        $scanner1 = $this->createMock(ScannerInterface::class);
        $vulnerability1 = new SQLInjectionVulnerability($tempFile, 1, '$query = "SELECT * FROM users WHERE id = " . $_GET["id"];', 'high');
        $collection1 = new VulnerabilityCollection();
        $collection1->add($vulnerability1);
        
        $scanner1->expects($this->once())
            ->method('scan')
            ->willReturn($collection1);
        
        $scanner2 = $this->createMock(ScannerInterface::class);
        $vulnerability2 = new SQLInjectionVulnerability($tempFile, 1, '$query = "SELECT * FROM users WHERE id = " . $_GET["id"];', 'medium');
        $collection2 = new VulnerabilityCollection();
        $collection2->add($vulnerability2);
        
        $scanner2->expects($this->once())
            ->method('scan')
            ->willReturn($collection2);
        
        // Create the analyzer and add the scanners
        $analyzer = new Analyzer();
        $analyzer->addScanner($scanner1);
        $analyzer->addScanner($scanner2);
        
        // Analyze the file
        $result = $analyzer->analyzeFile($tempFile);
        
        // Check the result
        $this->assertCount(2, $result);
        
        // Clean up
        unlink($tempFile);
    }
    
    public function testAnalyzeFileThrowsExceptionForNonExistentFile(): void
    {
        $analyzer = new Analyzer();
        
        $this->expectException(\InvalidArgumentException::class);
        $analyzer->analyzeFile('/path/to/nonexistent/file.php');
    }
    
    public function testAnalyzeDirectoryThrowsExceptionForNonExistentDirectory(): void
    {
        $analyzer = new Analyzer();
        
        $this->expectException(\InvalidArgumentException::class);
        $analyzer->analyzeDirectory('/path/to/nonexistent/directory');
    }
}