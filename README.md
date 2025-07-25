# 🛡️ Guardrails AI Security Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Guardrails AI](https://img.shields.io/badge/Powered%20by-Guardrails%20AI-green.svg)](https://github.com/guardrails-ai/guardrails)

A comprehensive, enterprise-grade security vulnerability scanner that uses AI-powered validation to detect security risks, compliance violations, and content safety issues in your codebase and content. Features an interactive dashboard with heatmaps, actionable recommendations, and detailed analytics.

## 🚀 Quick Start

```bash
# Install dependencies
pip install guardrails-ai plotly pandas numpy

# Clone and run the scanner
git clone <repository-url>
cd guardrails-security-scanner

# Scan a directory and generate dashboard
python scanner.py /path/to/your/code

# Open the generated dashboard
open security_dashboard.html
```

## 📋 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Dashboard Overview](#dashboard-overview)
- [Configuration](#configuration)
- [CI/CD Integration](#cicd-integration)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

### 🔍 Multi-Vector Security Analysis
- **PII Detection**: Identifies personally identifiable information (emails, phone numbers, SSNs, credit cards)
- **Secrets Scanning**: Detects API keys, passwords, tokens, and other sensitive credentials
- **Toxicity Analysis**: Flags inappropriate, offensive, or harmful content
- **Bias Detection**: Identifies potentially discriminatory language based on gender, race, religion, age
- **Data Leakage Prevention**: Prevents sensitive information exposure

### 📊 Interactive Security Dashboard
- **Real-time Vulnerability Heatmaps**: Visual representation of security issues by file and type
- **Executive Summary Cards**: Key metrics at a glance
- **Severity Distribution Charts**: Risk prioritization with color-coded severity levels
- **Trend Analysis**: Historical vulnerability patterns and improvements
- **Responsive Design**: Works on desktop and mobile devices

### 🎯 Actionable Intelligence
- **Prioritized Recommendations**: Risk-based remediation guidance
- **Step-by-Step Instructions**: Detailed fix procedures for developers
- **Best Practice Integration**: Industry-standard security patterns
- **Compliance Mapping**: GDPR, CCPA, HIPAA requirement alignment
- **Custom Action Plans**: Tailored recommendations based on findings

### 🔧 Developer-Friendly Integration
- **Multiple Input Formats**: Text strings, individual files, entire directories
- **Flexible Output Options**: Text reports, JSON data, interactive HTML dashboards
- **CI/CD Ready**: Seamless integration with build pipelines
- **Configurable Thresholds**: Customizable sensitivity levels
- **Extensible Architecture**: Easy to add new validators and rules

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Dependencies Installation

```bash
# Core dependencies
pip install guardrails-ai

# Visualization dependencies
pip install plotly pandas numpy

# Optional: Install all at once
pip install guardrails-ai plotly pandas numpy
```

### Verification

```bash
python -c "import guardrails, plotly, pandas, numpy; print('All dependencies installed successfully!')"
```

## 🚀 Usage

### Command Line Interface

#### Basic Usage

```bash
# Scan text directly
python scanner.py "Your text content here"

# Scan a single file
python scanner.py path/to/file.py

# Scan entire directory
python scanner.py /path/to/project/

# Generate dashboard (default behavior)
python scanner.py /path/to/code --output dashboard
```

#### Advanced Options

```bash
# Custom dashboard filename
python scanner.py /path/to/code --dashboard-file my_security_report.html

# Specific file extensions
python scanner.py /path/to/code --extensions .py .js .ts .jsx

# JSON output for integration
python scanner.py /path/to/code --output json

# Text report
python scanner.py /path/to/code --output text

# Use custom configuration
python scanner.py /path/to/code --config security_config.json
```

### Programmatic Usage

```python
from scanner import ContentSafetyScanner, DashboardGenerator

# Initialize scanner
scanner = ContentSafetyScanner()

# Scan text content
results = scanner.scan_text("Sample text with potential issues")

# Scan files
file_results = scanner.scan_file("app.py")

# Scan directory
directory_results = scanner.scan_directory("/path/to/project")

# Generate dashboard
dashboard = DashboardGenerator(scanner)
dashboard.generate_dashboard("my_report.html")
```

## 📊 Dashboard Overview

The security dashboard provides comprehensive visualization of your security posture:

### Executive Summary
- **Total Scans**: Number of validation checks performed
- **Files Scanned**: Count of files analyzed
- **Passed Scans**: Successful validations without issues
- **Vulnerabilities Found**: Total security issues detected

### Visualizations

#### 🔥 Vulnerability Heatmap
Interactive heatmap showing:
- Files with security issues (Y-axis)
- Types of vulnerabilities (X-axis)
- Color intensity indicating severity and frequency

#### 📈 Severity Distribution
Pie chart displaying:
- Critical vulnerabilities (immediate action required)
- High-risk issues (priority remediation)
- Medium-risk concerns (planned fixes)
- Low-risk observations (best practice improvements)

#### 📊 Vulnerability Trends
Bar chart showing:
- Count of each vulnerability type
- Relative frequency of issues
- Priority areas for security improvement

### 💡 Actionable Recommendations

Each vulnerability type includes:
- **Risk Level**: Critical, High, Medium, Low
- **Description**: Clear explanation of the security issue
- **Action Items**: Specific steps to remediate
- **Best Practices**: Preventive measures for the future

## ⚙️ Configuration

### Configuration File Format

Create a `config.json` file to customize scanner behavior:

```json
{
  "toxicity_threshold": 0.8,
  "pii_entities": [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER", 
    "CREDIT_CARD",
    "SSN",
    "PERSON",
    "LOCATION"
  ],
  "secret_patterns": [
    "api_key",
    "secret_key", 
    "password",
    "token",
    "access_token"
  ],
  "bias_types": [
    "gender",
    "race", 
    "religion",
    "age",
    "nationality"
  ]
}
```

### Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `toxicity_threshold` | float | 0.8 | Sensitivity level for toxicity detection (0.0-1.0) |
| `pii_entities` | array | See example | Types of PII to detect |
| `secret_patterns` | array | See example | Patterns for secret detection |
| `bias_types` | array | See example | Categories of bias to identify |

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.8
    - name: Install dependencies
      run: |
        pip install guardrails-ai plotly pandas numpy
    - name: Run security scan
      run: |
        python scanner.py . --output json > security_results.json
    - name: Upload results
      uses: actions/upload-artifact@v2
      with:
        name: security-scan-results
        path: security_results.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install guardrails-ai plotly pandas numpy'
                sh 'python scanner.py . --output dashboard'
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security_dashboard.html',
                    reportName: 'Security Scan Report'
                ])
            }
        }
    }
}
```

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - pip install guardrails-ai plotly pandas numpy
    - python scanner.py . --output json
  artifacts:
    reports:
      junit: security_results.json
    paths:
      - security_dashboard.html
    expire_in: 1 week
```

## 📚 API Reference

### ContentSafetyScanner Class

#### `__init__(config: Optional[Dict] = None)`
Initialize the scanner with optional configuration.

#### `scan_text(text: str, file_path: Optional[str] = None) -> List[ScanResult]`
Scan a text string for vulnerabilities.

#### `scan_file(file_path: str) -> List[ScanResult]`
Scan a single file for security issues.

#### `scan_directory(directory_path: str, file_extensions: List[str] = None) -> Dict[str, List[ScanResult]]`
Scan all files in a directory matching specified extensions.

### DashboardGenerator Class

#### `__init__(scanner: ContentSafetyScanner)`
Initialize dashboard generator with scanner results.

#### `generate_dashboard(output_file: str = "security_dashboard.html") -> str`
Generate HTML dashboard with visualizations and recommendations.

### ScanResult DataClass

```python
@dataclass
class ScanResult:
    validator_name: str      # Type of validation performed
    passed: bool            # Whether validation passed
    file_path: Optional[str] # File path (if applicable)
    error_message: Optional[str] # Error details
    details: Optional[Dict]  # Additional information
    severity: str           # Risk level: low, medium, high, critical
    line_number: Optional[int] # Line number (if applicable)
```

## 💡 Examples

### Example 1: Basic File Scan

```bash
# Scan a Python file
python scanner.py app.py

# Output: security_dashboard.html
```

### Example 2: Directory Scan with Custom Config

```bash
# Create config file
cat > my_config.json << EOF
{
  "toxicity_threshold": 0.9,
  "pii_entities": ["EMAIL_ADDRESS", "PHONE_NUMBER"]
}
EOF

# Run scan
python scanner.py /path/to/project --config my_config.json
```

### Example 3: Integration Script

```python
#!/usr/bin/env python3
import sys
from scanner import ContentSafetyScanner

def check_code_security(file_path):
    scanner = ContentSafetyScanner()
    results = scanner.scan_file(file_path)
    
    critical_issues = [r for r in results if not r.passed and r.severity == 'critical']
    
    if critical_issues:
        print(f"❌ Critical security issues found in {file_path}")
        for issue in critical_issues:
            print(f"  - {issue.validator_name}: {issue.error_message}")
        sys.exit(1)
    else:
        print(f"✅ No critical security issues found in {file_path}")

if __name__ == "__main__":
    check_code_security(sys.argv[1])
```

### Example 4: Bulk Analysis

```python
import os
from scanner import ContentSafetyScanner, DashboardGenerator

def analyze_multiple_projects(project_paths):
    scanner = ContentSafetyScanner()
    
    for project_path in project_paths:
        print(f"Scanning {project_path}...")
        scanner.scan_directory(project_path)
    
    # Generate comprehensive dashboard
    dashboard = DashboardGenerator(scanner)
    dashboard.generate_dashboard("comprehensive_security_report.html")
    
    print("Analysis complete! Check comprehensive_security_report.html")

# Usage
projects = ["/path/to/project1", "/path/to/project2", "/path/to/project3"]
analyze_multiple_projects(projects)
```

## 🔧 Troubleshooting

### Common Issues

#### Import Errors
```bash
# Error: ModuleNotFoundError: No module named 'guardrails'
pip install guardrails-ai

# Error: ModuleNotFoundError: No module named 'plotly'
pip install plotly pandas numpy
```

#### Permission Errors
```bash
# Error: Permission denied when scanning directories
chmod +r /path/to/scan
# or run with sudo if necessary
```

#### Memory Issues with Large Files
```python
# For very large files, process in chunks
def scan_large_file(file_path, chunk_size=10000):
    scanner = ContentSafetyScanner()
    results = []
    
    with open(file_path, 'r') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            results.extend(scanner.scan_text(chunk, file_path))
    
    return results
```

### Performance Optimization

#### For Large Codebases
- Use specific file extensions to limit scope
- Implement parallel processing for multiple files
- Consider excluding vendor/node_modules directories

#### Dashboard Generation
- For projects with >1000 files, consider sampling
- Use JSON output for integration with other tools
- Generate dashboards periodically rather than on every scan

## 🤝 Contributing

We welcome contributions to improve the Guardrails AI Security Scanner!

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd guardrails-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt
pip install -e .
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=scanner --cov-report=html
```

### Code Quality

```bash
# Format code
black scanner.py

# Lint code
flake8 scanner.py

# Type checking
mypy scanner.py
```

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Guardrails AI](https://github.com/guardrails-ai/guardrails) for the core validation framework
- [Plotly](https://plotly.com/) for interactive visualizations
- The open-source security community for inspiration and best practices

## 📞 Support

- 📧 Email: security-scanner-support@yourcompany.com
- 💬 Slack: #security-scanner
- 🐛 Issues: [GitHub Issues](https://github.com/yourorg/guardrails-security-scanner/issues)
- 📖 Documentation: [Wiki](https://github.com/yourorg/guardrails-security-scanner/wiki)

## 🗺️ Roadmap

### Version 2.0 (Q4 2025)
- [ ] Machine learning-based vulnerability prediction
- [ ] Integration with popular IDEs (VS Code, IntelliJ)
- [ ] Real-time scanning during development
- [ ] Advanced compliance reporting (SOX, HIPAA)

### Version 2.1 (Q1 2026)
- [ ] Custom validator development framework
- [ ] Team collaboration features
- [ ] Historical trend analysis
- [ ] Automated remediation suggestions

### Version 3.0 (Q2 2026)
- [ ] Cloud-native deployment options
- [ ] Enterprise single sign-on integration
- [ ] Advanced AI-powered risk assessment
- [ ] Multi-language support expansion

---

**Made with ❤️ by the Security Engineering Team**

*Protecting your code, one scan at a time.*