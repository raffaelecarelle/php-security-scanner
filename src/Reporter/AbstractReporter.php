<?php

namespace Security\CodeAnalyzer\Reporter;

use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Abstract base class for all vulnerability reporters.
 */
abstract class AbstractReporter implements ReporterInterface
{
    /**
     * @var string
     */
    protected string $name;

    /**
     * @var string
     */
    protected string $format;

    /**
     * AbstractReporter constructor.
     *
     * @param string $name
     * @param string $format
     */
    public function __construct(string $name, string $format)
    {
        $this->name = $name;
        $this->format = $format;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function getFormat(): string
    {
        return $this->format;
    }

    /**
     * Get a summary of the vulnerabilities.
     *
     * @param VulnerabilityCollection $vulnerabilities
     * @return array
     */
    protected function getSummary(VulnerabilityCollection $vulnerabilities): array
    {
        $summary = [
            'total' => count($vulnerabilities),
            'by_severity' => [
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0,
                'info' => 0,
            ],
            'by_type' => [],
        ];

        foreach ($vulnerabilities as $vulnerability) {
            // Count by severity
            $severity = $vulnerability->getSeverity();
            if (isset($summary['by_severity'][$severity])) {
                $summary['by_severity'][$severity]++;
            }

            // Count by type
            $type = $vulnerability->getType();
            if (!isset($summary['by_type'][$type])) {
                $summary['by_type'][$type] = 0;
            }
            $summary['by_type'][$type]++;
        }

        return $summary;
    }

    /**
     * {@inheritdoc}
     */
    abstract public function generate(VulnerabilityCollection $vulnerabilities): string;
}
