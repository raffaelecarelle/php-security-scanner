<?php

namespace Security\CodeAnalyzer\Command;

use Security\CodeAnalyzer\Analyzer\Analyzer;
use Security\CodeAnalyzer\Reporter\ConsoleReporter;
use Security\CodeAnalyzer\Reporter\JSONReporter;
use Security\CodeAnalyzer\Scanner\CommandInjectionScanner;
use Security\CodeAnalyzer\Scanner\SQLInjectionScanner;
use Security\CodeAnalyzer\Scanner\XSSScanner;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Command to analyze PHP code for security vulnerabilities.
 */
class AnalyzeCommand extends Command
{
    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setName('analyze')
            ->setDescription('Analyze PHP code for security vulnerabilities')
            ->addArgument(
                'path',
                InputArgument::REQUIRED,
                'Path to the file or directory to analyze'
            )
            ->addOption(
                'format',
                'f',
                InputOption::VALUE_OPTIONAL,
                'Output format (text, json)',
                'text'
            )
            ->addOption(
                'output',
                'o',
                InputOption::VALUE_OPTIONAL,
                'Output file (if not specified, output to stdout)'
            )
            ->addOption(
                'extensions',
                'e',
                InputOption::VALUE_OPTIONAL,
                'Comma-separated list of file extensions to analyze',
                'php'
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $path = $input->getArgument('path');
        $format = $input->getOption('format');
        $outputFile = $input->getOption('output');
        $extensions = explode(',', $input->getOption('extensions'));

        // Validate path
        if (!file_exists($path)) {
            $io->error(sprintf('Path "%s" does not exist.', $path));
            return Command::FAILURE;
        }

        // Create analyzer and add scanners
        $analyzer = new Analyzer();
        $analyzer->addScanner(new SQLInjectionScanner());
        $analyzer->addScanner(new XSSScanner());
        $analyzer->addScanner(new CommandInjectionScanner());

        // Analyze the path
        $io->section('Analyzing code for security vulnerabilities...');
        $startTime = microtime(true);

        try {
            if (is_dir($path)) {
                $vulnerabilities = $analyzer->analyzeDirectory($path, $extensions);
            } else {
                $vulnerabilities = $analyzer->analyzeFile($path);
            }

            $endTime = microtime(true);
            $duration = round($endTime - $startTime, 2);

            // Generate report
            $reporter = $format === 'json' ? new JSONReporter() : new ConsoleReporter();
            $report = $reporter->generate($vulnerabilities);

            // Output report
            if ($outputFile) {
                file_put_contents($outputFile, $report);
                $io->success(sprintf(
                    'Analysis completed in %s seconds. Found %d vulnerabilities. Report saved to %s',
                    $duration,
                    count($vulnerabilities),
                    $outputFile
                ));
            } else {
                if ($format === 'text') {
                    $output->writeln($report);
                } else {
                    $output->writeln($report);
                }

                $io->success(sprintf(
                    'Analysis completed in %s seconds. Found %d vulnerabilities.',
                    $duration,
                    count($vulnerabilities)
                ));
            }

            return count($vulnerabilities) > 0 ? Command::FAILURE : Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error(sprintf('Error during analysis: %s', $e->getMessage()));
            return Command::FAILURE;
        }
    }
}
