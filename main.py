import re
from collections import defaultdict, Counter
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
import json
import logging
from typing import Dict, List, Tuple, Set
import csv
from dataclasses import dataclass
import concurrent.futures
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('log_analysis.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class LogEntry:
    """Data class to store parsed log entry information."""
    ip: str
    timestamp: datetime
    method: str
    endpoint: str
    status_code: int
    response_size: int
    message: str = ""

class LogAnalyzer:
    def __init__(self, log_file: str, failed_login_threshold: int = 10):
        """Initialize the log analyzer with configuration parameters."""
        self.log_file = Path(log_file)
        self.failed_login_threshold = failed_login_threshold
        self.log_pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+).*?\[(.+?)\]\s*"(\w+)\s+([^\s]+)[^"]*"\s*(\d+)\s+(\d+)(?:\s+"([^"]*)")?'
        )
        self.entries: List[LogEntry] = []
        
    def parse_log_file(self) -> None:
        """Parse the log file and store structured data."""
        logging.info(f"Starting to parse log file: {self.log_file}")
        
        try:
            with open(self.log_file, 'r') as f:
                for line in tqdm(f, desc="Parsing log entries"):
                    match = self.log_pattern.match(line)
                    if match:
                        ip, timestamp_str, method, endpoint, status, size, message = match.groups()
                        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S +0000')
                        
                        self.entries.append(LogEntry(
                            ip=ip,
                            timestamp=timestamp,
                            method=method,
                            endpoint=endpoint,
                            status_code=int(status),
                            response_size=int(size),
                            message=message if message else ""
                        ))
                        
        except Exception as e:
            logging.error(f"Error parsing log file: {e}")
            raise
            
        logging.info(f"Successfully parsed {len(self.entries)} log entries")

    def analyze_ip_requests(self) -> Dict[str, int]:
        """Analyze requests per IP address."""
        ip_counts = Counter(entry.ip for entry in self.entries)
        return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))

    def analyze_endpoints(self) -> Dict[str, dict]:
        """Analyze endpoint access patterns."""
        endpoint_stats = defaultdict(lambda: {'count': 0, 'methods': Counter(), 'avg_response_size': 0})
        
        for entry in self.entries:
            stats = endpoint_stats[entry.endpoint]
            stats['count'] += 1
            stats['methods'][entry.method] += 1
            stats['avg_response_size'] = (
                (stats['avg_response_size'] * (stats['count'] - 1) + entry.response_size) / stats['count']
            )
            
        return dict(sorted(endpoint_stats.items(), key=lambda x: x[1]['count'], reverse=True))

    def detect_suspicious_activity(self) -> Dict[str, dict]:
        """Detect various types of suspicious activities."""
        suspicious_ips = defaultdict(lambda: {
            'failed_logins': 0,
            'high_frequency_requests': 0,
            'unusual_methods': set(),
            'large_responses': 0
        })

        # Time windows for rate limiting analysis (in seconds)
        RATE_WINDOW = 60
        REQUEST_THRESHOLD = 10
        LARGE_RESPONSE_THRESHOLD = 1000

        ip_time_windows = defaultdict(list)

        for entry in self.entries:
            # Track failed logins
            if entry.status_code == 401:
                suspicious_ips[entry.ip]['failed_logins'] += 1

            # Track high-frequency requests
            ip_time_windows[entry.ip].append(entry.timestamp)
            recent_requests = [
                t for t in ip_time_windows[entry.ip]
                if (entry.timestamp - t).total_seconds() <= RATE_WINDOW
            ]
            ip_time_windows[entry.ip] = recent_requests
            
            if len(recent_requests) > REQUEST_THRESHOLD:
                suspicious_ips[entry.ip]['high_frequency_requests'] += 1

            # Track unusual HTTP methods
            if entry.method not in {'GET', 'POST', 'PUT', 'DELETE'}:
                suspicious_ips[entry.ip]['unusual_methods'].add(entry.method)

            # Track large responses
            if entry.response_size > LARGE_RESPONSE_THRESHOLD:
                suspicious_ips[entry.ip]['large_responses'] += 1

        return {
            ip: stats for ip, stats in suspicious_ips.items()
            if any(value > 0 if isinstance(value, (int, float)) else value 
                  for value in stats.values())
        }

    def generate_visualizations(self, output_dir: str = 'analysis_output'):
        """Generate visualizations of the analysis results."""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Plot requests per IP
        ip_requests = self.analyze_ip_requests()
        plt.figure(figsize=(12, 6))
        plt.bar(list(ip_requests.keys())[:10], list(ip_requests.values())[:10])
        plt.title('Top 10 IPs by Request Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f'{output_dir}/ip_requests.png')
        plt.close()

        # Plot endpoint access patterns
        endpoint_stats = self.analyze_endpoints()
        endpoints = list(endpoint_stats.keys())[:10]
        counts = [stats['count'] for stats in endpoint_stats.values()][:10]
        
        plt.figure(figsize=(12, 6))
        plt.bar(endpoints, counts)
        plt.title('Top 10 Endpoints by Access Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f'{output_dir}/endpoint_access.png')
        plt.close()

    def save_results(self, output_dir: str = 'analysis_output'):
        """Save analysis results to various formats."""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Save to CSV
        results = {
            'ip_requests': self.analyze_ip_requests(),
            'endpoints': self.analyze_endpoints(),
            'suspicious_activity': self.detect_suspicious_activity()
        }
        
        # Save IP requests
        with open(f'{output_dir}/ip_requests.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in results['ip_requests'].items():
                writer.writerow([ip, count])

        # Save endpoint analysis
        with open(f'{output_dir}/endpoint_analysis.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Endpoint', 'Total Requests', 'HTTP Methods', 'Avg Response Size'])
            for endpoint, stats in results['endpoints'].items():
                writer.writerow([
                    endpoint,
                    stats['count'],
                    dict(stats['methods']),
                    f"{stats['avg_response_size']:.2f}"
                ])

        # Save suspicious activity
        with open(f'{output_dir}/suspicious_activity.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'IP Address',
                'Failed Logins',
                'High Frequency Requests',
                'Unusual Methods',
                'Large Responses'
            ])
            for ip, stats in results['suspicious_activity'].items():
                writer.writerow([
                    ip,
                    stats['failed_logins'],
                    stats['high_frequency_requests'],
                    ', '.join(stats['unusual_methods']),
                    stats['large_responses']
                ])

        # Save complete analysis as JSON
        with open(f'{output_dir}/complete_analysis.json', 'w') as f:
            # Convert sets to lists for JSON serialization
            json_results = {
                'ip_requests': results['ip_requests'],
                'endpoints': results['endpoints'],
                'suspicious_activity': {
                    ip: {
                        k: list(v) if isinstance(v, set) else v
                        for k, v in stats.items()
                    }
                    for ip, stats in results['suspicious_activity'].items()
                }
            }
            json.dump(json_results, f, indent=2)

def main():
    """Main function to run the log analysis."""
    log_file = 'sample.log'
    analyzer = LogAnalyzer(log_file)
    
    try:
        # Perform analysis
        analyzer.parse_log_file()
        analyzer.generate_visualizations()
        analyzer.save_results()
        
        logging.info("Analysis completed successfully")
        
        # Print summary to console
        print("\n=== Log Analysis Summary ===")
        print("\nTop 5 IPs by Request Count:")
        for ip, count in list(analyzer.analyze_ip_requests().items())[:5]:
            print(f"{ip:<15} {count:>5}")
            
        print("\nTop 5 Endpoints:")
        for endpoint, stats in list(analyzer.analyze_endpoints().items())[:5]:
            print(f"{endpoint:<20} {stats['count']:>5} requests")
            
        print("\nSuspicious Activity:")
        for ip, stats in analyzer.detect_suspicious_activity().items():
            if stats['failed_logins'] >= analyzer.failed_login_threshold:
                print(f"{ip:<15} {stats['failed_logins']:>5} failed login attempts")
                
    except Exception as e:
        logging.error(f"Error during analysis: {e}")
        raise

if __name__ == "__main__":
    main()
