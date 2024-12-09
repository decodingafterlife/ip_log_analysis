# Log Analysis Tool

A comprehensive log file analyzer that processes web server logs to detect patterns, suspicious activities, and generate detailed reports with visualizations.

## Features

- Parse and analyze web server log files
- Track requests per IP address
- Analyze endpoint access patterns
- Detect suspicious activities including:
  - Failed login attempts
  - High-frequency requests
  - Unusual HTTP methods
  - Large response patterns
- Generate visualizations for quick insights
- Export analysis results in multiple formats (CSV, JSON)
- Comprehensive logging system

## Requirements

- Python 3.7+
- See `requirements.txt` for package dependencies

## Installation

1. Clone this repository
2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Place your log file in the project directory (default expected name: `sample.log`)
2. Run the analyzer:
   ```bash
   python log_analyzer.py
   ```

The tool will create an `analysis_output` directory containing:
- Visualization plots (PNG format)
- Detailed analysis reports (CSV format)
- Complete analysis results (JSON format)
- Analysis logs (`log_analysis.log`)

## Configuration

You can modify the following parameters in the `LogAnalyzer` class:
- `failed_login_threshold`: Threshold for failed login attempts (default: 10)
- `RATE_WINDOW`: Time window for rate limiting analysis (default: 60 seconds)
- `REQUEST_THRESHOLD`: Request threshold for high-frequency detection (default: 10)
- `LARGE_RESPONSE_THRESHOLD`: Threshold for large response detection (default: 1000 bytes)

## Output Files

The analysis generates several output files:
- `ip_requests.csv`: Summary of requests per IP address
- `endpoint_analysis.csv`: Detailed endpoint access patterns
- `suspicious_activity.csv`: List of suspicious activities detected
- `complete_analysis.json`: Complete analysis results in JSON format
- `ip_requests.png`: Visualization of top IP requesters
- `endpoint_access.png`: Visualization of endpoint access patterns

## Logging

The tool maintains detailed logs in `log_analysis.log`, capturing both file operations and analysis steps. Logs are written to both file and console output.

## Error Handling

The tool includes comprehensive error handling and logging for:
- File operations
- Log parsing
- Analysis operations
- Data export operations
