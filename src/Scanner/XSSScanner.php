<?php

namespace Security\CodeAnalyzer\Scanner;

use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Stmt\Echo_;
use PhpParser\Node\Stmt\Expression;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Include_;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;
use Security\CodeAnalyzer\Vulnerability\XSSVulnerability;

class XSSScanner extends AbstractScanner
{
    /**
     * XSSScanner constructor.
     */
    public function __construct()
    {
        parent::__construct(
            'XSS Scanner',
            'Scans for Cross-Site Scripting (XSS) vulnerabilities in output functions'
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function scanAst(
        array $ast,
        string $code,
        string $filePath,
        VulnerabilityCollection $vulnerabilities
    ): void {
        $traverser = new NodeTraverser();
        $visitor = new class ($code, $filePath, $vulnerabilities) extends NodeVisitorAbstract {
            private string $code;
            private string $filePath;
            private VulnerabilityCollection $vulnerabilities;
            private array $sanitizedVariables = [];

            // List of functions that escape output
            private array $safeFunctions = [
                'htmlspecialchars',
                'htmlentities',
                'strip_tags',
                'addslashes',
                'escapeshellarg',
                'escapeshellcmd'
            ];

            public function __construct(string $code, string $filePath, VulnerabilityCollection $vulnerabilities)
            {
                $this->code = $code;
                $this->filePath = $filePath;
                $this->vulnerabilities = $vulnerabilities;
            }

            public function enterNode(Node $node)
            {
                // Track sanitized variables
                if ($node instanceof Expression && $node->expr instanceof Assign) {
                    $this->trackSanitizedAssignment($node->expr);
                }

                // Check for echo statements
                if ($node instanceof Echo_) {
                    foreach ($node->exprs as $expr) {
                        if ($this->isVulnerableExpression($expr)) {
                            $this->addVulnerability($node);
                            break;
                        }
                    }
                }

                // Check for print expressions
                if ($node instanceof Print_) {
                    if ($this->isVulnerableExpression($node->expr)) {
                        $this->addVulnerability($node);
                    }
                }

                // Check for include statements with variables
                if ($node instanceof Include_) {
                    if ($node->expr instanceof Variable) {
                        $this->addVulnerability($node);
                    }
                }

                return null;
            }

            private function trackSanitizedAssignment(Assign $assign): void
            {
                if ($assign->var instanceof Variable && is_string($assign->var->name)) {
                    $variableName = $assign->var->name;

                    // Check if the assignment is a sanitization function call
                    if ($assign->expr instanceof FuncCall && $assign->expr->name instanceof Node\Name) {
                        $functionName = $assign->expr->name->toString();

                        if (in_array($functionName, $this->safeFunctions)) {
                            $this->sanitizedVariables[$variableName] = true;
                        }
                    }
                }
            }

            private function isVulnerableExpression(Node $node): bool
            {
                // If it's a variable, check if it's sanitized
                if ($node instanceof Variable && is_string($node->name)) {
                    return !isset($this->sanitizedVariables[$node->name]);
                }

                // If it's a concatenation, check both sides
                if ($node instanceof Node\Expr\BinaryOp\Concat) {
                    return $this->isVulnerableExpression($node->left) ||
                        $this->isVulnerableExpression($node->right);
                }

                // If it's a function call, check if it's a safe function
                if ($node instanceof FuncCall && $node->name instanceof Node\Name) {
                    $functionName = $node->name->toString();

                    // If it's a safe function, it's not vulnerable
                    if (in_array($functionName, $this->safeFunctions)) {
                        return false;
                    }
                }

                return false;
            }

            private function addVulnerability(Node $node): void
            {
                $startLine = $node->getStartLine();
                $endLine = $node->getEndLine();

                // Extract the code snippet
                $lines = explode("\n", $this->code);
                $snippet = implode("\n", array_slice($lines, $startLine - 1, $endLine - $startLine + 1));

                $vulnerability = new XSSVulnerability(
                    $this->filePath,
                    $startLine,
                    $snippet,
                    'medium'
                );

                $this->vulnerabilities->add($vulnerability);
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);
    }
}
