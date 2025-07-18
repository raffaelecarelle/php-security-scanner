<?php

namespace Security\CodeAnalyzer\Reporter;

use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Reporter that generates reports in a console-friendly format.
 */
class ConsoleReporter extends AbstractReporter
{
    /**
     * @var array
     */
    private array $colors = [
        'reset' => "\033[0m",
        'red' => "\033[31m",
        'green' => "\033[32m",
        'yellow' => "\033[33m",
        'blue' => "\033[34m",
        'magenta' => "\033[35m",
        'cyan' => "\033[36m",
        'white' => "\033[37m",
        'bold' => "\033[1m",
    ];

    /**
     * @var array
     */
    private array $severityColors = [
        'critical' => 'red',
        'high' => 'red',
        'medium' => 'yellow',
        'low' => 'blue',
        'info' => 'cyan',
    ];

    /**
     * ConsoleReporter constructor.
     */
    public function __construct()
    {
        parent::__construct('Console Reporter', 'text');
    }

    /**
     * {@inheritdoc}
     */
    public function generate(VulnerabilityCollection $vulnerabilities): string
    {
        $summary = $this->getSummary($vulnerabilities);
        $output = [];

        // Add header
        $output[] = $this->color('bold', '=== Security Vulnerability Report ===');
        $output[] = '';

        // Add summary
        $output[] = $this->color('bold', 'Summary:');
        $output[] = sprintf('Total vulnerabilities found: %d', $summary['total']);
        $output[] = '';

        // Add severity breakdown
        $output[] = $this->color('bold', 'Vulnerabilities by Severity:');
        foreach ($summary['by_severity'] as $severity => $count) {
            if ($count > 0) {
                $output[] = sprintf('  %s: %d', $this->colorSeverity($severity, ucfirst($severity)), $count);
            }
        }
        $output[] = '';

        // Add type breakdown
        $output[] = $this->color('bold', 'Vulnerabilities by Type:');
        foreach ($summary['by_type'] as $type => $count) {
            $output[] = sprintf('  %s: %d', $type, $count);
        }
        $output[] = '';

        // Add detailed vulnerabilities
        if (count($vulnerabilities) > 0) {
            $output[] = $this->color('bold', 'Detailed Vulnerabilities:');
            $output[] = str_repeat('-', 80);

            $i = 1;
            foreach ($vulnerabilities as $vulnerability) {
                $output[] = sprintf(
                    '%d. %s (%s)',
                    $i++,
                    $this->color('bold', $vulnerability->getType()),
                    $this->colorSeverity($vulnerability->getSeverity(), $vulnerability->getSeverity())
                );
                $output[] = sprintf('   File: %s', $vulnerability->getFilePath());
                $output[] = sprintf('   Line: %d', $vulnerability->getLineNumber());
                $output[] = '   Code:';
                $output[] = '   ' . str_replace("\n", "\n   ", $vulnerability->getCodeSnippet());
                $output[] = '   Description:';
                $output[] = '   ' . wordwrap($vulnerability->getDescription(), 76, "\n   ");
                $output[] = '   Suggestion:';
                $output[] = '   ' . wordwrap($vulnerability->getSuggestion(), 76, "\n   ");
                $output[] = str_repeat('-', 80);
            }
        }

        return implode("\n", $output);
    }

    /**
     * Apply color to text.
     *
     * @param string $color
     * @param string $text
     * @return string
     */
    private function color(string $color, string $text): string
    {
        if (!isset($this->colors[$color]) || !$this->supportsColors()) {
            return $text;
        }

        return $this->colors[$color] . $text . $this->colors['reset'];
    }

    /**
     * Apply severity color to text.
     *
     * @param string $severity
     * @param string $text
     * @return string
     */
    private function colorSeverity(string $severity, string $text): string
    {
        if (!isset($this->severityColors[$severity])) {
            return $text;
        }

        return $this->color($this->severityColors[$severity], $text);
    }

    /**
     * Check if the current terminal supports colors.
     *
     * @return bool
     */
    private function supportsColors(): bool
    {
        // Check for Windows
        if (DIRECTORY_SEPARATOR === '\\') {
            return false !== getenv('ANSICON') || 'ON' === getenv('ConEmuANSI') || 'xterm' === getenv('TERM');
        }

        // Check for non-Windows
        return function_exists('posix_isatty') && @posix_isatty(STDOUT);
    }
}
