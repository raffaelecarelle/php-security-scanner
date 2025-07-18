<?php

namespace Security\CodeAnalyzer\Reporter;

use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Reporter that generates reports in JSON format.
 */
class JSONReporter extends AbstractReporter
{
    /**
     * JSONReporter constructor.
     */
    public function __construct()
    {
        parent::__construct('JSON Reporter', 'json');
    }

    /**
     * {@inheritdoc}
     */
    public function generate(VulnerabilityCollection $vulnerabilities): string
    {
        $summary = $this->getSummary($vulnerabilities);

        $report = [
            'summary' => $summary,
            'vulnerabilities' => [],
        ];

        foreach ($vulnerabilities as $vulnerability) {
            $report['vulnerabilities'][] = [
                'type' => $vulnerability->getType(),
                'severity' => $vulnerability->getSeverity(),
                'file' => $vulnerability->getFilePath(),
                'line' => $vulnerability->getLineNumber(),
                'code' => $vulnerability->getCodeSnippet(),
                'description' => $vulnerability->getDescription(),
                'suggestion' => $vulnerability->getSuggestion(),
            ];
        }

        return json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
