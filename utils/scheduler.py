import asyncio
import schedule
import time
import smtplib
import json
import yaml
from email.mime.text import MIMEText
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

class ScanScheduler:
    def __init__(self, config_file: str = "scan_config.yaml"):
        self.config_file = config_file
        self.config = self.load_config()
        self.running = False
        self.last_results = {}

    def load_config(self) -> Dict:
        """Load scheduler configuration from YAML file"""
        try:
            if Path(self.config_file).exists():
                with open(self.config_file, 'r') as f:
                    return yaml.safe_load(f)
            return self.get_default_config()
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.get_default_config()

    def get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'schedule': {
                'interval': 'daily',  # daily, hourly, or cron expression
                'time': '00:00'       # For daily scans
            },
            'targets': [],
            'notifications': {
                'email': {
                    'enabled': False,
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'from_address': '',
                    'to_addresses': []
                },
                'webhook': {
                    'enabled': False,
                    'url': '',
                    'headers': {}
                }
            },
            'alert_conditions': {
                'new_ports': True,
                'closed_ports': True,
                'service_changes': True,
                'critical_vulnerabilities': True
            }
        }

    def save_config(self) -> None:
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f)
        except Exception as e:
            print(f"Error saving config: {e}")

    async def send_email_notification(self, subject: str, body: str) -> None:
        """Send email notification"""
        if not self.config['notifications']['email']['enabled']:
            return

        email_config = self.config['notifications']['email']
        try:
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = email_config['from_address']
            msg['To'] = ', '.join(email_config['to_addresses'])

            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls()
                server.login(email_config['username'], email_config['password'])
                server.send_message(msg)
        except Exception as e:
            print(f"Error sending email notification: {e}")

    async def send_webhook_notification(self, data: Dict) -> None:
        """Send webhook notification"""
        if not self.config['notifications']['webhook']['enabled']:
            return

        webhook_config = self.config['notifications']['webhook']
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_config['url'],
                    json=data,
                    headers=webhook_config['headers']
                ) as response:
                    if response.status not in (200, 201, 202):
                        print(f"Webhook notification failed: {response.status}")
        except Exception as e:
            print(f"Error sending webhook notification: {e}")

    def compare_results(self, new_results: Dict, old_results: Dict) -> List[str]:
        """Compare scan results and generate alerts based on conditions"""
        alerts = []
        
        # Check for new or closed ports
        if self.config['alert_conditions']['new_ports']:
            new_ports = set(new_results.keys()) - set(old_results.keys())
            if new_ports:
                alerts.append(f"New open ports detected: {', '.join(map(str, new_ports))}")
        
        if self.config['alert_conditions']['closed_ports']:
            closed_ports = set(old_results.keys()) - set(new_results.keys())
            if closed_ports:
                alerts.append(f"Previously open ports now closed: {', '.join(map(str, closed_ports))}")
        
        # Check for service changes
        if self.config['alert_conditions']['service_changes']:
            for port in set(new_results.keys()) & set(old_results.keys()):
                if new_results[port]['service'] != old_results[port]['service']:
                    alerts.append(
                        f"Service change on port {port}: "
                        f"{old_results[port]['service']} → {new_results[port]['service']}"
                    )
        
        # Check for critical vulnerabilities
        if self.config['alert_conditions']['critical_vulnerabilities']:
            for port, data in new_results.items():
                if data.get('cve_data'):
                    cves = json.loads(data['cve_data'])
                    critical_cves = [
                        cve for cve in cves 
                        if isinstance(cve.get('score'), (int, float)) and cve['score'] >= 9.0
                    ]
                    if critical_cves:
                        alerts.append(
                            f"Critical vulnerabilities found for service on port {port}: "
                            f"{', '.join(cve['id'] for cve in critical_cves)}"
                        )
        
        return alerts

    async def run_scheduled_scan(self) -> None:
        """Execute scheduled scan and process results"""
        from scanner.tcp import TCPScanner
        from scanner.udp import UDPScanner

        try:
            # Initialize scanners
            tcp_scanner = TCPScanner()
            udp_scanner = UDPScanner()

            # Run scans
            for target in self.config['targets']:
                ip = target['ip']
                ports = target.get('ports')
                
                # Store previous results for comparison
                old_results = self.last_results.get(ip, {})
                
                # Run TCP and UDP scans
                await tcp_scanner.scan_ports(ip, ports)
                await udp_scanner.scan_ports(ip, ports)
                
                # Get new results from database
                new_results = {}  # TODO: Implement result retrieval from database
                
                # Compare results and generate alerts
                alerts = self.compare_results(new_results, old_results)
                
                # Send notifications if there are alerts
                if alerts:
                    notification_text = "\n".join(alerts)
                    subject = f"Port Scan Alerts for {ip}"
                    
                    await self.send_email_notification(subject, notification_text)
                    await self.send_webhook_notification({
                        "ip": ip,
                        "timestamp": datetime.now().isoformat(),
                        "alerts": alerts
                    })
                
                # Update stored results
                self.last_results[ip] = new_results

        except Exception as e:
            print(f"Error during scheduled scan: {e}")
        finally:
            await tcp_scanner.close()
            await udp_scanner.close()

    async def start(self) -> None:
        """Start the scheduler"""
        self.running = True
        
        while self.running:
            schedule_config = self.config['schedule']
            
            if schedule_config['interval'] == 'daily':
                schedule.every().day.at(schedule_config['time']).do(
                    lambda: asyncio.create_task(self.run_scheduled_scan())
                )
            elif schedule_config['interval'] == 'hourly':
                schedule.every().hour.do(
                    lambda: asyncio.create_task(self.run_scheduled_scan())
                )
            else:
                # Custom cron expression
                schedule.every().day.at(schedule_config['interval']).do(
                    lambda: asyncio.create_task(self.run_scheduled_scan())
                )
            
            while self.running:
                schedule.run_pending()
                await asyncio.sleep(60)  # Check schedule every minute

    async def stop(self) -> None:
        """Stop the scheduler"""
        self.running = False
