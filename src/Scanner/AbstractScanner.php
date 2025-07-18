<?php

namespace Security\CodeAnalyzer\Scanner;

use PhpParser\Error;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\NodeVisitor\NameResolver;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Abstract base class for all vulnerability scanners.
 */
abstract class AbstractScanner implements ScannerInterface
{
    /**
     * @var string
     */
    protected string $name;

    /**
     * @var string
     */
    protected string $description;

    /**
     * AbstractScanner constructor.
     *
     * @param string $name
     * @param string $description
     */
    public function __construct(string $name, string $description)
    {
        $this->name = $name;
        $this->description = $description;
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
    public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * {@inheritdoc}
     */
    public function scan(string $code, string $filePath): VulnerabilityCollection
    {
        $vulnerabilities = new VulnerabilityCollection();

        try {
            $parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
            $ast = $parser->parse($code);

            if ($ast === null) {
                return $vulnerabilities;
            }

            // Resolve names
            $nameResolver = new NameResolver();
            $traverser = new NodeTraverser();
            $traverser->addVisitor($nameResolver);
            $ast = $traverser->traverse($ast);

            // Scan the AST for vulnerabilities
            $this->scanAst($ast, $code, $filePath, $vulnerabilities);

        } catch (Error $e) {
            // Parsing error, skip this file
            // In a real-world application, we might want to log this
        }

        return $vulnerabilities;
    }

    /**
     * Scan the AST for vulnerabilities.
     *
     * @param array $ast The abstract syntax tree
     * @param string $code The original code
     * @param string $filePath The path to the file being scanned
     * @param VulnerabilityCollection $vulnerabilities Collection to add found vulnerabilities to
     */
    abstract protected function scanAst(
        array $ast,
        string $code,
        string $filePath,
        VulnerabilityCollection $vulnerabilities
    ): void;
}
