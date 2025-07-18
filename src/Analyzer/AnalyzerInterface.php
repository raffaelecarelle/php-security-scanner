<?php

namespace Security\CodeAnalyzer\Analyzer;

use Security\CodeAnalyzer\Scanner\ScannerInterface;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Interface for the security code analyzer.
 */
interface AnalyzerInterface
{
    /**
     * Add a scanner to the analyzer.
     *
     * @param ScannerInterface $scanner
     * @return self
     */
    public function addScanner(ScannerInterface $scanner): self;

    /**
     * Get all registered scanners.
     *
     * @return ScannerInterface[]
     */
    public function getScanners(): array;

    /**
     * Analyze a single file for vulnerabilities.
     *
     * @param string $filePath Path to the file to analyze
     * @return VulnerabilityCollection
     */
    public function analyzeFile(string $filePath): VulnerabilityCollection;

    /**
     * Analyze a directory recursively for vulnerabilities.
     *
     * @param string $directoryPath Path to the directory to analyze
     * @param array $fileExtensions File extensions to analyze (default: ['php'])
     * @return VulnerabilityCollection
     */
    public function analyzeDirectory(string $directoryPath, array $fileExtensions = ['php']): VulnerabilityCollection;
}
