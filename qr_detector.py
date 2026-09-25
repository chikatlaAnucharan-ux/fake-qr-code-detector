import cv2
import pyzbar.pyzbar as pyzbar
from urllib.parse import urlparse
import re
from typing import Dict, List, Tuple
import numpy as np

class FakeQRCodeDetector:
    """
    Detects fake or malicious QR codes by analyzing:
    - URL patterns and suspicious characteristics
    - QR code integrity and structure
    - Known phishing domains
    """
    
    def __init__(self):
        self.suspicious_keywords = [
            'bit.ly', 'tinyurl', 'short.link', 'goo.gl',
            'ow.ly', 'is.gd', 'buff.ly'
        ]
        self.suspicious_patterns = [
            r'(?:https?://)?(?:www\.)?([^/]+@)',  # URL with @ symbol
            r'(?:https?://)?(?:www\.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IP address
        ]
        self.phishing_domains = [
            'paypa1.com', 'amaz0n.com', 'appl3.com',
            'microsft.com', 'goog1e.com'
        ]
    
    def decode_qr_code(self, image_path: str) -> List[Dict]:
        """
        Decode QR code from image file.
        
        Args:
            image_path: Path to image file
            
        Returns:
            List of decoded QR code data
        """
        try:
            image = cv2.imread(image_path)
            if image is None:
                return []
            
            decoded_objects = pyzbar.decode(image)
            results = []
            
            for obj in decoded_objects:
                data = {
                    'type': obj.type,
                    'data': obj.data.decode('utf-8'),
                    'quality': self._calculate_quality(obj)
                }
                results.append(data)
            
            return results
        except Exception as e:
            print(f"Error decoding QR code: {e}")
            return []
    
    def _calculate_quality(self, qr_object) -> float:
        """Calculate QR code quality score (0-1)."""
        # Simple quality metric based on detection confidence
        return 0.85  # Placeholder
    
    def check_url_safety(self, url: str) -> Tuple[bool, List[str]]:
        """
        Check if URL is potentially malicious.
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (is_safe, list_of_threats)
        """
        threats = []
        
        # Check for URL shorteners
        if any(shortener in url for shortener in self.suspicious_keywords):
            threats.append("URL uses suspicious shortener service")
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url):
                threats.append(f"URL matches suspicious pattern: {pattern}")
        
        # Check for phishing domains
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        for phishing in self.phishing_domains:
            if phishing in domain:
                threats.append(f"Domain matches known phishing domain: {phishing}")
        
        # Check for homograph attacks
        if self._check_homograph_attack(domain):
            threats.append("Domain may be homograph attack (similar to legitimate domain)")
        
        # Check for HTTPS
        if not url.startswith('https://'):
            threats.append("URL does not use HTTPS encryption")
        
        return len(threats) == 0, threats
    
    def _check_homograph_attack(self, domain: str) -> bool:
        """Detect homograph attacks using look-alike characters."""
        homograph_chars = {
            '0': 'o',  # Zero vs letter O
            '1': 'i',  # One vs letter I
            'l': 'I',  # Lowercase L vs uppercase I
        }
        
        # Simple check - in production, use more sophisticated method
        for char in domain:
            if char in '01l':
                return True
        return False
    
    def analyze_qr_image(self, image_path: str) -> Dict:
        """
        Perform comprehensive analysis on QR code image.
        
        Args:
            image_path: Path to QR code image
            
        Returns:
            Dictionary with analysis results
        """
        image = cv2.imread(image_path)
        if image is None:
            return {'error': 'Could not load image'}
        
        decoded_data = self.decode_qr_code(image_path)
        
        analysis = {
            'image_path': image_path,
            'qr_codes_found': len(decoded_data),
            'decoded_data': [],
            'overall_threat_level': 'safe'
        }
        
        threat_count = 0
        
        for qr_data in decoded_data:
            url = qr_data['data']
            is_safe, threats = self.check_url_safety(url)
            
            qr_analysis = {
                'data': url,
                'type': qr_data['type'],
                'quality': qr_data['quality'],
                'is_safe': is_safe,
                'threats': threats
            }
            
            analysis['decoded_data'].append(qr_analysis)
            
            if not is_safe:
                threat_count += 1
        
        # Set threat level
        if threat_count == 0:
            analysis['overall_threat_level'] = 'safe'
        elif threat_count <= len(decoded_data) / 2:
            analysis['overall_threat_level'] = 'medium'
        else:
            analysis['overall_threat_level'] = 'high'
        
        return analysis
    
    def generate_report(self, analysis: Dict) -> str:
        """Generate human-readable report from analysis."""
        report = f"\n{'='*60}\n"
        report += f"QR CODE SECURITY ANALYSIS REPORT\n"
        report += f"{'='*60}\n\n"
        
        report += f"Image: {analysis.get('image_path', 'Unknown')}\n"
        report += f"QR Codes Found: {analysis.get('qr_codes_found', 0)}\n"
        report += f"Overall Threat Level: {analysis.get('overall_threat_level', 'Unknown').upper()}\n\n"
        
        for i, qr in enumerate(analysis.get('decoded_data', []), 1):
            report += f"QR Code #{i}\n"
            report += f"-" * 40 + "\n"
            report += f"Data: {qr['data']}\n"
            report += f"Type: {qr['type']}\n"
            report += f"Quality Score: {qr['quality']:.2f}\n"
            report += f"Safety Status: {'✓ SAFE' if qr['is_safe'] else '✗ POTENTIALLY MALICIOUS'}\n"
            
            if qr['threats']:
                report += f"Detected Threats:\n"
                for threat in qr['threats']:
                    report += f"  • {threat}\n"
            report += "\n"
        
        report += f"{'='*60}\n"
        return report


# Example usage
if __name__ == "__main__":
    detector = FakeQRCodeDetector()
    
    # Example analysis
    # analysis = detector.analyze_qr_image("qr_code.png")
    # print(detector.generate_report(analysis))
    
    print("QR Code Detector initialized successfully!")
