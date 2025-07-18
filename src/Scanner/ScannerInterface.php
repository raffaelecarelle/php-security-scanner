<?php

namespace Security\CodeAnalyzer\Scanner;

use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Interface for all vulnerability scanners.
 */
interface ScannerInterface
{
    /**
     * Scan the given code for vulnerabilities.
     *
     * @param string $code The PHP code to scan
     * @param string $filePath The path to the file being scanned
     * @return VulnerabilityCollection Collection of found vulnerabilities
     */
    public function scan(string $code, string $filePath): VulnerabilityCollection;

    /**
     * Get the name of the scanner.
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Get the description of what this scanner checks for.
     *
     * @return string
     */
    public function getDescription(): string;
}
