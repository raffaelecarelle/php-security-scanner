<?php

namespace Security\CodeAnalyzer\Scanner;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use Security\CodeAnalyzer\Vulnerability\SQLInjectionVulnerability;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

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
            private array $vulnerableVariables = [];

            public function __construct(string $code, string $filePath, VulnerabilityCollection $vulnerabilities)
            {
                $this->code = $code;
                $this->filePath = $filePath;
                $this->vulnerabilities = $vulnerabilities;
            }

            public function enterNode(Node $node)
            {
                // Track variable assignments with concatenation
                if ($node instanceof Assign) {
                    if ($node->var instanceof Variable && isset($node->var->name)) {
                        $varName = $node->var->name;
                        if ($this->containsVariableConcatenation($node->expr)) {
                            $this->vulnerableVariables[$varName] = $node;
                        }
                    }
                }

                // Check for direct query execution with concatenated variables
                if ($node instanceof MethodCall) {
                    $methodName = null;
                    if (isset($node->name->name)) {
                        $methodName = $node->name->name;
                    }

                    // Check for common database query methods
                    if (in_array($methodName, ['query', 'exec', 'execute', 'rawQuery'])) {
                        // Check if any argument contains a concatenation with a variable
                        foreach ($node->args as $arg) {
                            if ($this->containsVariableConcatenation($arg->value)) {
                                $this->addVulnerability($node);
                                break;
                            }

                            if ($arg->value instanceof Variable && isset($arg->value->name)) {
                                // Check if the variable was assigned a concatenated value
                                $varName = $arg->value->name;
                                if (isset($this->vulnerableVariables[$varName])) {
                                    $this->addVulnerabilityWithAssignment($node, $this->vulnerableVariables[$varName]);
                                    break;
                                }
                            }
                        }
                    }
                }

                // Check for mysqli_query and similar functions
                if ($node instanceof FuncCall && $node->name instanceof Node\Name) {
                    $functionName = $node->name->toString();

                    if (in_array($functionName, ['mysqli_query', 'mysql_query', 'pg_query'])) {
                        $queryArgIndex = ($functionName === 'mysqli_query') ? 1 : 0;

                        if (isset($node->args[$queryArgIndex])) {
                            $queryArg = $node->args[$queryArgIndex]->value;

                            if ($this->containsVariableConcatenation($queryArg)) {
                                $this->addVulnerability($node);
                            } elseif ($queryArg instanceof Variable && isset($queryArg->name)) {
                                // Check if the variable was assigned a concatenated value
                                $varName = $queryArg->name;
                                if (isset($this->vulnerableVariables[$varName])) {
                                    $this->addVulnerabilityWithAssignment($node, $this->vulnerableVariables[$varName]);
                                }
                            }
                        }
                    }
                }

                return null;
            }

            private function containsVariableConcatenation(Node $node): bool
            {
                if ($node instanceof Concat) {
                    // Check if either side is a variable or contains a variable
                    return $this->hasVariable($node->left) || $this->hasVariable($node->right) ||
                        $this->containsVariableConcatenation($node->left) ||
                        $this->containsVariableConcatenation($node->right);
                }

                return false;
            }

            private function hasVariable(Node $node): bool
            {
                if ($node instanceof Variable) {
                    return true;
                }

                if ($node instanceof Concat) {
                    return $this->hasVariable($node->left) || $this->hasVariable($node->right);
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

            private function addVulnerabilityWithAssignment(Node $callNode, Node $assignNode): void
            {
                $assignStartLine = $assignNode->getStartLine();
                $callStartLine = $callNode->getStartLine();
                $callEndLine = $callNode->getEndLine();

                // Extract the code snippet including both assignment and call
                $lines = explode("\n", $this->code);
                $startLine = min($assignStartLine, $callStartLine);
                $endLine = max($assignStartLine, $callEndLine);

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
