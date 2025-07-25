#!/usr/bin/env python3
"""
Guardrails AI Content Safety Scanner with Dashboard
isi.idemudia
This script uses Guardrails AI validators to scan content for various safety issues
and generates an interactive dashboard with heatmaps and recommendations.

Requirements:
pip install guardrails-ai plotly pandas numpy
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import argparse
from collections import defaultdict, Counter

try:
    import guardrails as gd
    # Try different import patterns for validators
    try:
        from guardrails.validators import (
            ToxicLanguage,
            PIIDetector,
        )
        VALIDATORS_AVAILABLE = True
    except ImportError:
        try:
            # Alternative import pattern
            from guardrails_community.validators import (
                ToxicLanguage,
                PIIDetector,
            )
            VALIDATORS_AVAILABLE = True
        except ImportError:
            print("Warning: Some validators not available. Installing basic text analysis...")
            VALIDATORS_AVAILABLE = False
            
    # For now, let's create mock validators for demonstration
    if not VALIDATORS_AVAILABLE:
        print("Using mock validators for demonstration. Install specific validator packages for full functionality.")
        
except ImportError as e:
    print(f"Error: guardrails-ai not installed properly. Details: {e}")
    print("Please run: pip install guardrails-ai")
    print("If issues persist, try: pip install --upgrade guardrails-ai")
    exit(1)

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import pandas as pd
    import numpy as np
except ImportError:
    print("Error: Required packages not installed. Run: pip install plotly pandas numpy")
    exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Data class to store scan results"""
    validator_name: str
    passed: bool
    file_path: Optional[str] = None
    error_message: Optional[str] = None
    details: Optional[Dict] = None
    severity: str = 'medium'  # low, medium, high, critical
    line_number: Optional[int] = None

@dataclass
class ScanStats:
    """Statistics about the scanning session"""
    total_files: int = 0
    total_scans: int = 0
    passed_scans: int = 0
    failed_scans: int = 0
    vulnerabilities_by_type: Dict[str, int] = None
    vulnerabilities_by_severity: Dict[str, int] = None
    vulnerabilities_by_file: Dict[str, int] = None
    scan_duration: float = 0.0
    
    def __post_init__(self):
        if self.vulnerabilities_by_type is None:
            self.vulnerabilities_by_type = {}
        if self.vulnerabilities_by_severity is None:
            self.vulnerabilities_by_severity = {}
        if self.vulnerabilities_by_file is None:
            self.vulnerabilities_by_file = {}

class ContentSafetyScanner:
    """Main scanner class that orchestrates various Guardrails validators"""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the scanner with optional configuration"""
        self.config = config or {}
        self.validators = self._initialize_validators()
        self.all_results: List[ScanResult] = []
        self.stats = ScanStats()
        
    def _initialize_validators(self) -> Dict[str, Any]:
        """Initialize all available validators"""
        validators = {}
        
        try:
            if VALIDATORS_AVAILABLE:
                # Try to initialize real validators
                try:
                    validators['toxicity'] = {
                        'validator': ToxicLanguage(
                            threshold=self.config.get('toxicity_threshold', 0.8)
                        ),
                        'severity': 'high'
                    }
                except Exception as e:
                    logger.warning(f"ToxicLanguage validator not available: {e}")
                
                try:
                    validators['pii'] = {
                        'validator': PIIDetector(
                            pii_entities=self.config.get('pii_entities', [
                                'EMAIL_ADDRESS', 'PHONE_NUMBER', 'CREDIT_CARD', 
                                'SSN', 'PERSON', 'LOCATION'
                            ])
                        ),
                        'severity': 'critical'
                    }
                except Exception as e:
                    logger.warning(f"PIIDetector validator not available: {e}")
            
            # Add basic pattern-based validators as fallback
            validators.update(self._initialize_basic_validators())
            
        except Exception as e:
            logger.warning(f"Some validators could not be initialized: {e}")
            # Fall back to basic validators
            validators = self._initialize_basic_validators()
            
        return validators
    
    def _initialize_basic_validators(self) -> Dict[str, Any]:
        """Initialize basic pattern-based validators as fallback"""
        import re
        
        class BasicPatternValidator:
            def __init__(self, patterns, name):
                self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
                self.name = name
            
            def validate(self, text):
                for pattern in self.patterns:
                    if pattern.search(text):
                        return MockResult(False, f"{self.name} pattern detected")
                return MockResult(True, "No issues found")
        
        class MockResult:
            def __init__(self, validation_passed, error_message=""):
                self.validation_passed = validation_passed
                self.error = error_message
                self.error_spans = None
        
        # Create basic validators using regex patterns
        basic_validators = {
            'secrets': {
                'validator': BasicPatternValidator([
                    r'api[_-]?key\s*[:=]\s*["\']?[\w\-]{16,}["\']?',
                    r'secret[_-]?key\s*[:=]\s*["\']?[\w\-]{16,}["\']?',
                    r'password\s*[:=]\s*["\']?[\w\-]{8,}["\']?',
                    r'token\s*[:=]\s*["\']?[\w\-]{16,}["\']?',
                    r'sk-[\w]{32,}',  # OpenAI API key pattern
                    r'ghp_[\w]{36}',  # GitHub token pattern
                ], 'Secret'),
                'severity': 'critical'
            },
            'pii': {
                'validator': BasicPatternValidator([
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone number
                    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                    r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',  # SSN
                ], 'PII'),
                'severity': 'critical'
            },
            'toxicity': {
                'validator': BasicPatternValidator([
                    r'\b(hate|stupid|idiot|moron|dumb)\b',
                    r'\b(kill|die|death)\s+(you|yourself|him|her)\b',
                ], 'Toxicity'),
                'severity': 'high'
            },
            'bias': {
                'validator': BasicPatternValidator([
                    r'\b(women|men)\s+(are|aren\'t|can\'t|should|shouldn\'t)\b',
                    r'\b(all|most)\s+(blacks|whites|asians|latinos|muslims|christians|jews)\b',
                ], 'Bias'),
                'severity': 'medium'
            }
        }
        
        return basic_validators
    
    def scan_text(self, text: str, file_path: Optional[str] = None) -> List[ScanResult]:
        """Scan text content using all available validators"""
        results = []
        
        for validator_name, validator_config in self.validators.items():
            try:
                logger.info(f"Running {validator_name} validator...")
                
                validator = validator_config['validator']
                severity = validator_config['severity']
                
                # Handle both real Guardrails validators and basic pattern validators
                if hasattr(validator, 'validate'):
                    # Basic pattern validator
                    result = validator.validate(text)
                else:
                    # Real Guardrails validator
                    guard = gd.Guard().use(validator)
                    result = guard.validate(text)
                
                scan_result = ScanResult(
                    validator_name=validator_name,
                    passed=result.validation_passed,
                    file_path=file_path,
                    severity=severity
                )
                
                if not result.validation_passed:
                    scan_result.error_message = str(result.error)
                    scan_result.details = result.error_spans if hasattr(result, 'error_spans') else None
                
                results.append(scan_result)
                self.all_results.append(scan_result)
                
            except Exception as e:
                logger.error(f"Error running {validator_name} validator: {e}")
                error_result = ScanResult(
                    validator_name=validator_name,
                    passed=False,
                    file_path=file_path,
                    error_message=f"Validator error: {str(e)}",
                    severity='medium'
                )
                results.append(error_result)
                self.all_results.append(error_result)
        
        return results
    
    def scan_file(self, file_path: str) -> List[ScanResult]:
        """Scan a file for vulnerabilities (supports text, CSV, JSON, etc.)"""
        try:
            file_extension = os.path.splitext(file_path)[1].lower()
            
            if file_extension == '.csv':
                return self.scan_csv_file(file_path)
            elif file_extension == '.json':
                return self.scan_json_file(file_path)
            else:
                # Regular text file scanning
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                logger.info(f"Scanning text file: {file_path}")
                return self.scan_text(content, file_path)
            
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            error_result = ScanResult(
                validator_name="file_read",
                passed=False,
                file_path=file_path,
                error_message=f"Could not read file: {str(e)}",
                severity='low'
            )
            self.all_results.append(error_result)
            return [error_result]
    
    def scan_csv_file(self, file_path: str) -> List[ScanResult]:
        """Scan a CSV file for vulnerabilities"""
        try:
            import csv
            results = []
            
            logger.info(f"Scanning CSV file: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8', newline='') as csvfile:
                # Try to detect delimiter
                sample = csvfile.read(1024)
                csvfile.seek(0)
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                
                reader = csv.reader(csvfile, delimiter=delimiter)
                headers = next(reader, [])
                
                # Scan headers for sensitive information
                header_text = " ".join(headers)
                header_results = self.scan_text(header_text, file_path)
                for result in header_results:
                    result.line_number = 1  # Header row
                results.extend(header_results)
                
                # Scan each row
                for row_num, row in enumerate(reader, start=2):  # Start at 2 because headers are row 1
                    row_text = " ".join(str(cell) for cell in row)
                    row_results = self.scan_text(row_text, file_path)
                    
                    # Add row number to results
                    for result in row_results:
                        result.line_number = row_num
                    
                    results.extend(row_results)
                    
                    # Limit scanning for very large CSV files (performance optimization)
                    if row_num > 1000:
                        logger.warning(f"Large CSV file detected. Scanned first 1000 rows only.")
                        break
            
            logger.info(f"CSV scan completed: {len(results)} validation checks")
            return results
            
        except Exception as e:
            logger.error(f"Error scanning CSV file {file_path}: {e}")
            error_result = ScanResult(
                validator_name="csv_scan",
                passed=False,
                file_path=file_path,
                error_message=f"Could not scan CSV file: {str(e)}",
                severity='low'
            )
            self.all_results.append(error_result)
            return [error_result]
    
    def scan_json_file(self, file_path: str) -> List[ScanResult]:
        """Scan a JSON file for vulnerabilities"""
        try:
            import json
            
            logger.info(f"Scanning JSON file: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convert JSON to text for scanning
            json_text = json.dumps(data, indent=2)
            results = self.scan_text(json_text, file_path)
            
            # Also scan individual values for more granular detection
            def scan_json_values(obj, path="root"):
                value_results = []
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        current_path = f"{path}.{key}"
                        if isinstance(value, str):
                            val_results = self.scan_text(value, file_path)
                            for result in val_results:
                                result.details = {"json_path": current_path}
                            value_results.extend(val_results)
                        elif isinstance(value, (dict, list)):
                            value_results.extend(scan_json_values(value, current_path))
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        current_path = f"{path}[{i}]"
                        if isinstance(item, str):
                            val_results = self.scan_text(item, file_path)
                            for result in val_results:
                                result.details = {"json_path": current_path}
                            value_results.extend(val_results)
                        elif isinstance(item, (dict, list)):
                            value_results.extend(scan_json_values(item, current_path))
                return value_results
            
            # Scan individual values
            value_results = scan_json_values(data)
            results.extend(value_results)
            
            logger.info(f"JSON scan completed: {len(results)} validation checks")
            return results
            
        except Exception as e:
            logger.error(f"Error scanning JSON file {file_path}: {e}")
            error_result = ScanResult(
                validator_name="json_scan",
                passed=False,
                file_path=file_path,
                error_message=f"Could not scan JSON file: {str(e)}",
                severity='low'
            )
            self.all_results.append(error_result)
            return [error_result]
    
    def scan_directory(self, directory_path: str, file_extensions: List[str] = None) -> Dict[str, List[ScanResult]]:
        """Scan all files in a directory"""
        if file_extensions is None:
            file_extensions = ['.txt', '.md', '.py', '.js', '.json', '.yaml', '.yml', '.csv', '.xml', '.html', '.sql']
        
        results = {}
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    results[file_path] = self.scan_file(file_path)
                    self.stats.total_files += 1
        
        return results
    
    def calculate_stats(self):
        """Calculate comprehensive statistics from all scan results"""
        self.stats.total_scans = len(self.all_results)
        self.stats.passed_scans = sum(1 for r in self.all_results if r.passed)
        self.stats.failed_scans = self.stats.total_scans - self.stats.passed_scans
        
        # Count vulnerabilities by type
        vuln_by_type = Counter()
        vuln_by_severity = Counter()
        vuln_by_file = Counter()
        
        for result in self.all_results:
            if not result.passed:
                vuln_by_type[result.validator_name] += 1
                vuln_by_severity[result.severity] += 1
                if result.file_path:
                    vuln_by_file[result.file_path] += 1
        
        self.stats.vulnerabilities_by_type = dict(vuln_by_type)
        self.stats.vulnerabilities_by_severity = dict(vuln_by_severity)
        self.stats.vulnerabilities_by_file = dict(vuln_by_file)

class DashboardGenerator:
    """Generates interactive HTML dashboard with visualizations"""
    
    def __init__(self, scanner: ContentSafetyScanner):
        self.scanner = scanner
        self.scanner.calculate_stats()
        
    def create_summary_cards(self) -> str:
        """Create summary statistics cards"""
        stats = self.scanner.stats
        
        return f"""
        <div class="summary-cards">
            <div class="card">
                <h3>Total Scans</h3>
                <div class="number">{stats.total_scans}</div>
            </div>
            <div class="card">
                <h3>Files Scanned</h3>
                <div class="number">{stats.total_files}</div>
            </div>
            <div class="card">
                <h3>Passed Scans</h3>
                <div class="number success">{stats.passed_scans}</div>
            </div>
            <div class="card">
                <h3>Vulnerabilities Found</h3>
                <div class="number danger">{stats.failed_scans}</div>
            </div>
        </div>
        """
    
    def create_vulnerability_heatmap(self) -> str:
        """Create heatmap showing vulnerabilities by file and type"""
        if not self.scanner.stats.vulnerabilities_by_file:
            return "<div class='chart-placeholder'>No file-specific vulnerabilities to display</div>"
        
        # Prepare data for heatmap
        files = list(self.scanner.stats.vulnerabilities_by_file.keys())
        validator_types = list(self.scanner.validators.keys())
        
        # Create matrix
        matrix = []
        for file_path in files:
            row = []
            for validator in validator_types:
                count = sum(1 for r in self.scanner.all_results 
                           if r.file_path == file_path and r.validator_name == validator and not r.passed)
                row.append(count)
            matrix.append(row)
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=matrix,
            x=validator_types,
            y=[os.path.basename(f) for f in files],
            colorscale='Reds',
            showscale=True,
            colorbar=dict(title="Vulnerability Count")
        ))
        
        fig.update_layout(
            title="Vulnerability Heatmap by File and Type",
            xaxis_title="Vulnerability Types",
            yaxis_title="Files",
            height=max(400, len(files) * 30),
            margin=dict(l=200, r=50, t=50, b=50)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id="heatmap")
    
    def create_severity_chart(self) -> str:
        """Create pie chart showing vulnerability distribution by severity"""
        if not self.scanner.stats.vulnerabilities_by_severity:
            return "<div class='chart-placeholder'>No vulnerabilities found</div>"
        
        severity_data = self.scanner.stats.vulnerabilities_by_severity
        
        colors = {
            'low': '#28a745',
            'medium': '#ffc107', 
            'high': '#fd7e14',
            'critical': '#dc3545'
        }
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_data.keys()),
            values=list(severity_data.values()),
            marker_colors=[colors.get(sev, '#6c757d') for sev in severity_data.keys()],
            hole=0.3
        )])
        
        fig.update_layout(
            title="Vulnerabilities by Severity Level",
            height=400
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id="severity-chart")
    
    def create_vulnerability_trends(self) -> str:
        """Create bar chart showing vulnerability types"""
        if not self.scanner.stats.vulnerabilities_by_type:
            return "<div class='chart-placeholder'>No vulnerabilities by type to display</div>"
        
        vuln_data = self.scanner.stats.vulnerabilities_by_type
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(vuln_data.keys()),
                y=list(vuln_data.values()),
                marker_color=['#dc3545', '#fd7e14', '#ffc107', '#28a745'][:len(vuln_data)]
            )
        ])
        
        fig.update_layout(
            title="Vulnerabilities by Type",
            xaxis_title="Vulnerability Types",
            yaxis_title="Count",
            height=400
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id="trends-chart")
    
    def generate_recommendations(self) -> str:
        """Generate actionable recommendations based on findings"""
        recommendations = []
        stats = self.scanner.stats
        
        # General recommendations
        if stats.failed_scans > 0:
            success_rate = (stats.passed_scans / stats.total_scans) * 100
            if success_rate < 70:
                recommendations.append({
                    'level': 'critical',
                    'title': 'Low Security Score',
                    'description': f'Only {success_rate:.1f}% of scans passed. Immediate security review required.',
                    'actions': [
                        'Conduct comprehensive security audit',
                        'Implement mandatory security training',
                        'Review and update security policies'
                    ]
                })
        
        # Specific vulnerability recommendations
        vuln_types = stats.vulnerabilities_by_type
        
        if vuln_types.get('secrets', 0) > 0:
            recommendations.append({
                'level': 'critical',
                'title': 'Secrets Detected',
                'description': f'Found {vuln_types["secrets"]} instances of exposed secrets.',
                'actions': [
                    'Immediately rotate all exposed API keys and secrets',
                    'Implement secrets management solution (e.g., HashiCorp Vault)',
                    'Set up pre-commit hooks to prevent secret commits',
                    'Use environment variables for sensitive data'
                ]
            })
        
        if vuln_types.get('pii', 0) > 0:
            recommendations.append({
                'level': 'high',
                'title': 'PII Exposure Risk',
                'description': f'Found {vuln_types["pii"]} instances of PII exposure.',
                'actions': [
                    'Review data handling procedures',
                    'Implement data anonymization techniques',
                    'Ensure GDPR/CCPA compliance',
                    'Set up automated PII detection in CI/CD pipeline'
                ]
            })
        
        if vuln_types.get('toxicity', 0) > 0:
            recommendations.append({
                'level': 'medium',
                'title': 'Content Quality Issues',
                'description': f'Found {vuln_types["toxicity"]} instances of toxic content.',
                'actions': [
                    'Review content moderation policies',
                    'Implement automated content filtering',
                    'Train content creators on appropriate language',
                    'Set up content review workflows'
                ]
            })
        
        if vuln_types.get('bias', 0) > 0:
            recommendations.append({
                'level': 'medium',
                'title': 'Bias Detection',
                'description': f'Found {vuln_types["bias"]} instances of potential bias.',
                'actions': [
                    'Review content for inclusive language',
                    'Implement bias detection in content pipeline',
                    'Provide diversity and inclusion training',
                    'Establish content review board'
                ]
            })
        
        # Success recommendations
        if stats.failed_scans == 0:
            recommendations.append({
                'level': 'success',
                'title': 'Excellent Security Posture',
                'description': 'No vulnerabilities detected in this scan.',
                'actions': [
                    'Maintain current security practices',
                    'Schedule regular security scans',
                    'Consider expanding scan coverage',
                    'Share best practices with team'
                ]
            })
        
        return self._format_recommendations(recommendations)
    
    def _format_recommendations(self, recommendations: List[Dict]) -> str:
        """Format recommendations as HTML"""
        html = "<div class='recommendations'>"
        
        level_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14', 
            'medium': '#ffc107',
            'success': '#28a745'
        }
        
        for rec in recommendations:
            color = level_colors.get(rec['level'], '#6c757d')
                            html += f"""
                <div class="rec-header">
                    <span class="rec-level" style="background-color: {color}">{rec['level'].upper()}</span>
                    <h4>{rec['title']}</h4>
                </div>
                <p>{rec['description']}</p>
                <ul class="actions">
                """
            for action in rec['actions']:
                html += f"<li>{action}</li>"
            html += "</ul></div>"
        
        html += "</div>"
        return html
    
    def generate_dashboard(self, output_file: str = "security_dashboard.html"):
        """Generate complete HTML dashboard"""
        
        # CSS styles
        css = """
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 30px; }
            .header h1 { color: #343a40; margin-bottom: 10px; }
            .header .timestamp { color: #6c757d; }
            .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
            .card h3 { margin: 0 0 10px 0; color: #6c757d; font-size: 14px; text-transform: uppercase; }
            .card .number { font-size: 32px; font-weight: bold; color: #343a40; }
            .card .number.success { color: #28a745; }
            .card .number.danger { color: #dc3545; }
            .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
            .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .chart-placeholder { text-align: center; color: #6c757d; padding: 40px; }
            .full-width { grid-column: 1 / -1; }
            .recommendations { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .recommendation { margin-bottom: 20px; padding: 15px; border-left: 4px solid #dee2e6; background-color: #f8f9fa; }
            .recommendation.critical { border-left-color: #dc3545; }
            .recommendation.high { border-left-color: #fd7e14; }
            .recommendation.medium { border-left-color: #ffc107; }
            .recommendation.success { border-left-color: #28a745; }
            .rec-header { display: flex; align-items: center; margin-bottom: 10px; }
            .rec-level { padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; margin-right: 10px; }
            .rec-header h4 { margin: 0; }
            .actions { margin: 10px 0 0 0; }
            .actions li { margin-bottom: 5px; }
            @media (max-width: 768px) { .charts-grid { grid-template-columns: 1fr; } }
        </style>
        """
        
        # Generate dashboard HTML
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Vulnerability Dashboard</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            {css}
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Security Vulnerability Dashboard</h1>
                    <div class="timestamp">Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
                
                {self.create_summary_cards()}
                
                <div class="charts-grid">
                    <div class="chart-container">
                        {self.create_severity_chart()}
                    </div>
                    <div class="chart-container">
                        {self.create_vulnerability_trends()}
                    </div>
                    <div class="chart-container full-width">
                        {self.create_vulnerability_heatmap()}
                    </div>
                </div>
                
                <div class="recommendations">
                    <h2>📋 Actionable Recommendations</h2>
                    {self.generate_recommendations()}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Write dashboard to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Dashboard generated: {output_file}")
        return output_file

def generate_report(results: List[ScanResult], output_format: str = 'text') -> str:
    """Generate a report from scan results"""
    if output_format == 'json':
        report_data = []
        for result in results:
            report_data.append(asdict(result))
        return json.dumps(report_data, indent=2)
    
    else:  # text format
        report = "=" * 60 + "\n"
        report += "GUARDRAILS AI CONTENT SAFETY SCAN REPORT\n"
        report += "=" * 60 + "\n\n"
        
        passed_count = sum(1 for r in results if r.passed)
        total_count = len(results)
        
        report += f"Summary: {passed_count}/{total_count} validators passed\n\n"
        
        for result in results:
            status = "✅ PASSED" if result.passed else "❌ FAILED"
            report += f"{result.validator_name.upper()}: {status}"
            if result.severity:
                report += f" (Severity: {result.severity.upper()})"
            report += "\n"
            
            if not result.passed and result.error_message:
                report += f"  Error: {result.error_message}\n"
                
            if result.details:
                report += f"  Details: {result.details}\n"
                
            report += "\n"
        
        return report

def main():
    """Main function to run the scanner from command line"""
    parser = argparse.ArgumentParser(description='Scan content for safety vulnerabilities using Guardrails AI')
    parser.add_argument('input', help='Input text, file path, or directory path')
    parser.add_argument('--type', choices=['text', 'file', 'directory'], default='auto',
                       help='Type of input (auto-detected by default)')
    parser.add_argument('--output', choices=['text', 'json', 'dashboard'], default='dashboard',
                       help='Output format')
    parser.add_argument('--config', help='Path to JSON configuration file')
    parser.add_argument('--extensions', nargs='+', default=['.txt', '.md', '.py', '.js', '.csv', '.json'],
                       help='File extensions to scan when scanning directories')
    parser.add_argument('--dashboard-file', default='security_dashboard.html',
                       help='Output file for dashboard')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Could not load config file: {e}")
            return
    
    # Initialize scanner
    start_time = datetime.datetime.now()
    scanner = ContentSafetyScanner(config)
    
    # Determine input type
    input_type = args.type
    if input_type == 'auto':
        if os.path.isfile(args.input):
            input_type = 'file'
        elif os.path.isdir(args.input):
            input_type = 'directory'
        else:
            input_type = 'text'
    
    # Perform scan
    if input_type == 'text':
        results = scanner.scan_text(args.input)
        
    elif input_type == 'file':
        results = scanner.scan_file(args.input)
        scanner.stats.total_files = 1
        
    elif input_type == 'directory':
        all_results = scanner.scan_directory(args.input, args.extensions)
        results = []
        for file_results in all_results.values():
            results.extend(file_results)
    
    # Calculate scan duration
    end_time = datetime.datetime.now()
    scanner.stats.scan_duration = (end_time - start_time).total_seconds()
    
    # Generate output
    if args.output == 'dashboard':
        dashboard = DashboardGenerator(scanner)
        dashboard_file = dashboard.generate_dashboard(args.dashboard_file)
        print(f"Dashboard generated: {dashboard_file}")
        print(f"Open {dashboard_file} in your browser to view the security dashboard")
        
        # Also print summary
        print(f"\nScan Summary:")
        print(f"Files scanned: {scanner.stats.total_files}")
        print(f"Total scans: {scanner.stats.total_scans}")
        print(f"Vulnerabilities found: {scanner.stats.failed_scans}")
        print(f"Success rate: {(scanner.stats.passed_scans/scanner.stats.total_scans)*100:.1f}%")
        
    else:
        print(generate_report(results, args.output))

if __name__ == "__main__":
    # Example usage
    if len(os.sys.argv) == 1:
        # Demo mode
        print("Running in demo mode...")
        
        # Example text with various issues
        demo_text = """
        Hello! My email is john.doe@example.com and my phone is 555-123-4567.
        My API key is sk-1234567890abcdef and password is secret123.
        This content might contain some offensive language.
        Women are not good at technical jobs and should focus on other areas.
        """
        
        scanner = ContentSafetyScanner()
        results = scanner.scan_text(demo_text)
        scanner.stats.total_files = 1
        
        # Generate dashboard
        dashboard = DashboardGenerator(scanner)
        dashboard_file = dashboard.generate_dashboard("demo_dashboard.html")
        
        print("Demo scan completed!")
        print(f"Dashboard generated: {dashboard_file}")
        print("Open demo_dashboard.html in your browser to view the results")
        
        print("\nTo use the scanner:")
        print("python script.py 'your text here'")
        print("python script.py path/to/file.txt")
        print("python script.py path/to/directory/")
    else:
        main()
