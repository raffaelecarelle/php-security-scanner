<?php

namespace Security\CodeAnalyzer\Scanner;

use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use Security\CodeAnalyzer\Vulnerability\SQLInjectionVulnerability;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Scanner for SQL Injection vulnerabilities.
 */
class SQLInjectionScanner extends AbstractScanner
{
    /**
     * SQLInjectionScanner constructor.
     */
    public function __construct()
    {
        parent::__construct(
            'SQL Injection Scanner',
            'Scans for SQL injection vulnerabilities in database queries'
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

            public function __construct(string $code, string $filePath, VulnerabilityCollection $vulnerabilities)
            {
                $this->code = $code;
                $this->filePath = $filePath;
                $this->vulnerabilities = $vulnerabilities;
            }

            public function enterNode(Node $node)
            {
                // Check for direct query execution with concatenated variables
                if ($node instanceof MethodCall) {
                    $methodName = $node->name->name ?? null;

                    // Check for common database query methods
                    if (in_array($methodName, ['query', 'exec', 'execute', 'rawQuery'])) {
                        // Check if any argument contains a concatenation with a variable
                        foreach ($node->args as $arg) {
                            if ($this->containsVariableConcatenation($arg->value)) {
                                $this->addVulnerability($node);
                                break;
                            }
                        }
                    }
                }

                // Check for mysqli_query and similar functions
                if ($node instanceof FuncCall && $node->name instanceof Node\Name) {
                    $functionName = $node->name->toString();

                    if (in_array($functionName, ['mysqli_query', 'mysql_query', 'pg_query'])) {
                        // For these functions, the SQL query is usually the second argument
                        if (isset($node->args[1]) && $this->containsVariableConcatenation($node->args[1]->value)) {
                            $this->addVulnerability($node);
                        }
                        // For mysql_query, the SQL query is the first argument
                        elseif ($functionName === 'mysql_query' && isset($node->args[0]) &&
                                $this->containsVariableConcatenation($node->args[0]->value)) {
                            $this->addVulnerability($node);
                        }
                    }
                }

                return null;
            }

            private function containsVariableConcatenation(Node $node): bool
            {
                if ($node instanceof Concat) {
                    if ($node->left instanceof Variable || $node->right instanceof Variable) {
                        return true;
                    }

                    return $this->containsVariableConcatenation($node->left) ||
                           $this->containsVariableConcatenation($node->right);
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

                $vulnerability = new SQLInjectionVulnerability(
                    $this->filePath,
                    $startLine,
                    $snippet,
                    'high'
                );

                $this->vulnerabilities->add($vulnerability);
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);
    }
}
