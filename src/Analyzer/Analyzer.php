<?php

namespace Security\CodeAnalyzer\Analyzer;

use Security\CodeAnalyzer\Scanner\ScannerInterface;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;
use Symfony\Component\Finder\Finder;

/**
 * Main analyzer class that coordinates the scanning process.
 */
class Analyzer implements AnalyzerInterface
{
    /**
     * @var ScannerInterface[]
     */
    private array $scanners = [];

    /**
     * {@inheritdoc}
     */
    public function addScanner(ScannerInterface $scanner): self
    {
        $this->scanners[] = $scanner;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getScanners(): array
    {
        return $this->scanners;
    }

    /**
     * {@inheritdoc}
     */
    public function analyzeFile(string $filePath): VulnerabilityCollection
    {
        if (!file_exists($filePath)) {
            throw new \InvalidArgumentException(sprintf('File "%s" does not exist.', $filePath));
        }

        $code = file_get_contents($filePath);
        $vulnerabilities = new VulnerabilityCollection();

        foreach ($this->scanners as $scanner) {
            $result = $scanner->scan($code, $filePath);
            $vulnerabilities->merge($result);
        }

        return $vulnerabilities;
    }

    /**
     * {@inheritdoc}
     */
    public function analyzeDirectory(string $directoryPath, array $fileExtensions = ['php']): VulnerabilityCollection
    {
        if (!is_dir($directoryPath)) {
            throw new \InvalidArgumentException(sprintf('Directory "%s" does not exist.', $directoryPath));
        }

        $finder = new Finder();
        $finder->files()
            ->in($directoryPath)
            ->name(array_map(function ($ext) {
                return sprintf('*.%s', $ext);
            }, $fileExtensions))
            ->sortByName();

        $vulnerabilities = new VulnerabilityCollection();

        foreach ($finder as $file) {
            $fileVulnerabilities = $this->analyzeFile($file->getRealPath());
            $vulnerabilities->merge($fileVulnerabilities);
        }

        return $vulnerabilities;
    }
}
