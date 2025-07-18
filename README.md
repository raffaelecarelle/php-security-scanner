# PHP Security Code Analyzer

A command-line tool that analyzes PHP code for security vulnerabilities and suggests how to fix them.

## Features

- Detects common security vulnerabilities in PHP code:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
- Provides detailed information about each vulnerability:
  - File path and line number
  - Code snippet
  - Description of the vulnerability
  - Severity level
  - Suggestions on how to fix the vulnerability
- Supports multiple output formats:
  - Text (console-friendly with colors)
  - JSON
- Can analyze individual files or entire directories recursively
- Can save reports to a file

## Requirements

- PHP 7.4 or higher
- Composer

## Installation

### Via Composer (recommended)

```bash
composer require security/code-analyzer
```

### Manual Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/php-security-code-analyzer.git
cd php-security-code-analyzer
```

2. Install dependencies:

```bash
composer install
```

3. Make the executable file executable:

```bash
chmod +x bin/security-analyzer
```

## Usage

### Basic Usage

Analyze a single file:

```bash
./bin/security-analyzer analyze path/to/file.php
```

Analyze a directory recursively:

```bash
./bin/security-analyzer analyze path/to/directory
```

### Output Formats

By default, the tool outputs a text report to the console. You can change the output format using the `--format` or `-f` option:

```bash
./bin/security-analyzer analyze path/to/file.php --format=json
```

Supported formats:
- `text` (default): Console-friendly text output with colors
- `json`: JSON output

### Save Report to File

You can save the report to a file using the `--output` or `-o` option:

```bash
./bin/security-analyzer analyze path/to/file.php --output=report.txt
```

### Specify File Extensions

By default, the tool analyzes files with the `.php` extension. You can specify additional file extensions using the `--extensions` or `-e` option:

```bash
./bin/security-analyzer analyze path/to/directory --extensions=php,phtml,inc
```

### Full Command Reference

```
Description:
  Analyze PHP code for security vulnerabilities

Usage:
  analyze [options] [--] <path>

Arguments:
  path                  Path to the file or directory to analyze

Options:
  -f, --format=FORMAT   Output format (text, json) [default: "text"]
  -o, --output=OUTPUT   Output file (if not specified, output to stdout)
  -e, --extensions=EXTENSIONS  Comma-separated list of file extensions to analyze [default: "php"]
  -h, --help            Display help for the given command
```

## Examples

### Analyze a Single File

```bash
./bin/security-analyzer analyze src/login.php
```

### Analyze a Directory with Custom Extensions

```bash
./bin/security-analyzer analyze src --extensions=php,phtml,inc
```

### Generate a JSON Report and Save to File

```bash
./bin/security-analyzer analyze src --format=json --output=security-report.json
```

## Architecture

The tool follows SOLID principles and Clean Code practices:

- **Single Responsibility Principle**: Each class has a single responsibility
- **Open/Closed Principle**: The tool is open for extension (new scanners, reporters) but closed for modification
- **Liskov Substitution Principle**: Subtypes can be substituted for their base types
- **Interface Segregation Principle**: Clients only depend on the interfaces they use
- **Dependency Inversion Principle**: High-level modules depend on abstractions, not concrete implementations

The main components are:

- **Vulnerability**: Represents a security vulnerability found in the code
- **Scanner**: Scans code for specific types of vulnerabilities
- **Analyzer**: Coordinates the scanning process
- **Reporter**: Generates reports in different formats

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Submit a pull request

## Testing

Run the tests using PHPUnit:

```bash
composer test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.