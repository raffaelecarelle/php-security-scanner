<?php

namespace Security\CodeAnalyzer\Tests\Command;

use PHPUnit\Framework\TestCase;
use Security\CodeAnalyzer\Command\AnalyzeCommand;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

class AnalyzeCommandTest extends TestCase
{
    private CommandTester $commandTester;
    
    protected function setUp(): void
    {
        $application = new Application();
        $application->add(new AnalyzeCommand());
        
        $command = $application->find('analyze');
        $this->commandTester = new CommandTester($command);
    }
    
    public function testExecuteWithNonExistentPath(): void
    {
        $this->commandTester->execute([
            'path' => '/path/to/nonexistent/file.php',
        ]);
        
        $output = $this->commandTester->getDisplay();
        $this->assertStringContainsString('does not exist', $output);
        $this->assertEquals(1, $this->commandTester->getStatusCode());
    }
    
    public function testExecuteWithValidFile(): void
    {
        // Create a temporary test file with a SQL injection vulnerability
        $tempFile = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tempFile, '<?php $query = "SELECT * FROM users WHERE id = " . $_GET["id"]; ?>');
        
        // Execute the command
        $this->commandTester->execute([
            'path' => $tempFile,
        ]);
        
        // Check the output
        $output = $this->commandTester->getDisplay();
        $this->assertStringContainsString('Analyzing code for security vulnerabilities', $output);
        $this->assertStringContainsString('Analysis completed', $output);
        
        // Clean up
        unlink($tempFile);
    }
    
    public function testExecuteWithJsonFormat(): void
    {
        // Create a temporary test file with a SQL injection vulnerability
        $tempFile = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tempFile, '<?php $query = "SELECT * FROM users WHERE id = " . $_GET["id"]; ?>');
        
        // Execute the command with JSON format
        $this->commandTester->execute([
            'path' => $tempFile,
            '--format' => 'json',
            '--output' => '/tmp/output.json',
        ]);

        // Try to decode the JSON
        $data = json_decode(file_get_contents('/tmp/output.json'), true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('vulnerabilities', $data);
        
        // Clean up
        unlink($tempFile);
    }
    
    public function testExecuteWithOutputFile(): void
    {
        // Create a temporary test file with a SQL injection vulnerability
        $tempFile = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tempFile, '<?php $query = "SELECT * FROM users WHERE id = " . $_GET["id"]; ?>');
        
        // Create a temporary output file
        $outputFile = tempnam(sys_get_temp_dir(), 'output_');
        
        // Execute the command with output file
        $this->commandTester->execute([
            'path' => $tempFile,
            '--output' => $outputFile,
        ]);
        
        // Check the output
        $output = $this->commandTester->getDisplay();
        $this->assertStringContainsString('Report saved to', $output);
        
        // Check the output file
        $this->assertFileExists($outputFile);
        $fileContent = file_get_contents($outputFile);
        $this->assertStringContainsString('Security Vulnerability Report', $fileContent);
        
        // Clean up
        unlink($tempFile);
        unlink($outputFile);
    }
}