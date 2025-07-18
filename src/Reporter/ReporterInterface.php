<?php

namespace Security\CodeAnalyzer\Reporter;

use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Interface for all vulnerability reporters.
 */
interface ReporterInterface
{
    /**
     * Generate a report from the given vulnerability collection.
     *
     * @param VulnerabilityCollection $vulnerabilities
     * @return string The formatted report
     */
    public function generate(VulnerabilityCollection $vulnerabilities): string;

    /**
     * Get the name of the reporter.
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Get the format of the report (e.g., 'text', 'json', 'html').
     *
     * @return string
     */
    public function getFormat(): string;
}
