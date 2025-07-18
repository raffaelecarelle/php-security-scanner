<?php

namespace Security\CodeAnalyzer\Scanner;

use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use Security\CodeAnalyzer\Vulnerability\CommandInjectionVulnerability;
use Security\CodeAnalyzer\Vulnerability\VulnerabilityCollection;

/**
 * Scanner for Command Injection vulnerabilities.
 */
class CommandInjectionScanner extends AbstractScanner
{
    /**
     * CommandInjectionScanner constructor.
     */
    public function __construct()
    {
        parent::__construct(
            'Command Injection Scanner',
            'Scans for command injection vulnerabilities in system command functions'
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

            // List of dangerous functions that execute system commands
            private array $dangerousFunctions = [
                'exec',
                'passthru',
                'system',
                'shell_exec',
                'popen',
                'proc_open',
                'pcntl_exec',
                '`', // Backtick operator
            ];

            public function __construct(string $code, string $filePath, VulnerabilityCollection $vulnerabilities)
            {
                $this->code = $code;
                $this->filePath = $filePath;
                $this->vulnerabilities = $vulnerabilities;
            }

            public function enterNode(Node $node)
            {
                // Check for function calls
                if ($node instanceof FuncCall && $node->name instanceof Node\Name) {
                    $functionName = $node->name->toString();

                    if (in_array($functionName, $this->dangerousFunctions)) {
                        // Check if any argument contains a variable
                        foreach ($node->args as $arg) {
                            if ($this->containsVariable($arg->value)) {
                                $this->addVulnerability($node);
                                break;
                            }
                        }
                    }
                }

                // Check for backtick operator (more complex, would need to check for `` syntax)
                // This is a simplified check
                if ($node instanceof Node\Scalar\Encapsed) {
                    foreach ($node->parts as $part) {
                        if ($part instanceof Variable) {
                            $this->addVulnerability($node);
                            break;
                        }
                    }
                }

                return null;
            }

            private function containsVariable(Node $node): bool
            {
                if ($node instanceof Variable) {
                    return true;
                }

                if ($node instanceof Concat) {
                    return $this->containsVariable($node->left) ||
                           $this->containsVariable($node->right);
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

                $vulnerability = new CommandInjectionVulnerability(
                    $this->filePath,
                    $startLine,
                    $snippet,
                    'critical'
                );

                $this->vulnerabilities->add($vulnerability);
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);
    }
}
