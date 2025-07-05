import time
import logging
from asgiref.sync import async_to_sync
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from .modules.detect_and_expand import is_shortened_url
from .modules.virustotal_checker import scan_url
from .modules.homograph_detector import is_homograph 
from .models import URLScanResult
import threading
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class Calculate_Suspicion(APIView):
    def post(self, request):
        start_time = time.time()
        logger.info("▶️ URL check started")

        url = request.data.get("url", "").strip()
        user_email = request.data.get("email")

        if not url or not user_email:
            logger.warning("❌ Missing URL or Email")
            return Response({"error": "Missing URL or Email"}, status=400)
        
        cached = URLScanResult.objects.filter(url=url).first()
        if cached:
            logger.info("⚡ Returned cached classification")
            classification = cached.classification
            reason = cached.reason
            if classification != "safe":
                self.send_alert(user_email, url, classification, reason)
            return Response({
                "classification": cached.classification,
                "reason": cached.reason,
                "details": {
                    "Cached": True
                }
            })

        # 1. Homograph check on original URL
        t1 = time.time()
        count, suspicious_chars = is_homograph(url)
        logger.info(f"🕵️ Homograph check (original): {round(time.time() - t1, 4)} sec")

        if count > 0:
            t2 = time.time()
            shortened, expanded = async_to_sync(is_shortened_url)(url)
            logger.info(f"🔗 Shortened check: {round(time.time() - t2, 4)} sec")
            self.send_alert(user_email, url, "suspicious", "Homograph characters detected")
            logger.info(f"⏱️ Total time: {round(time.time() - start_time, 4)} sec")
            return Response({
                "classification": "suspicious",
                "reason": "Detected homograph characters in URL",
                "details": {
                    "Is_shortened": shortened,
                    "Expanded URL": expanded,
                    "Suspicious Characters": suspicious_chars
                }
            })

        # 2. Expand the URL
        t3 = time.time()
        shortened, expanded = async_to_sync(is_shortened_url)(url)
        logger.info(f"🔗 URL expansion: {round(time.time() - t3, 4)} sec")

        # 3. Homograph check on expanded URL
        t4 = time.time()
        count, suspicious_chars = is_homograph(expanded)
        logger.info(f"🕵️ Homograph check (expanded): {round(time.time() - t4, 4)} sec")

        if count > 0:
            self.send_alert(user_email, expanded, "suspicious", "Homograph characters detected after expansion")
            logger.info(f"⏱️ Total time: {round(time.time() - start_time, 4)} sec")
            return Response({
                "classification": "suspicious",
                "reason": "Detected homograph characters in expanded URL",
                "details": {
                    "Is_shortened": shortened,
                    "Expanded URL": expanded,
                    "Suspicious Characters": suspicious_chars
                }
            })

        # 4. Scan with VirusTotal
        t5 = time.time()
        stats = async_to_sync(scan_url)(expanded)
        logger.info(f"🛡️ VirusTotal scan: {round(time.time() - t5, 4)} sec")

        # 5. Classification decision
        classification = "safe"
        reason = ""
        if stats["malicious"] > 0:
            classification = "malicious"
            reason = "Detected as malicious by VirusTotal"
        elif stats["suspicious"] > 0:
            classification = "suspicious"
            reason = "Detected as suspicious by VirusTotal"

        if classification != "safe":
            self.send_alert(user_email, expanded, classification, reason)

        URLScanResult.objects.create(url=url, classification=classification, reason=reason)

        logger.info(f"✅ Final classification: {classification.upper()}")
        logger.info(f"⏱️ Total processing time: {round(time.time() - start_time, 4)} sec")

        return Response({
            "classification": classification,
            "reason": reason,
            "details": {
                "Is_shortened": shortened,
                "Expanded URL": expanded,
            }
        })

    def send_alert(self, email, url, status, reason):
        threading.Thread(
            target=self._send_alert_email,
            args=(email, url, status, reason),
            daemon=True  # Ensure thread exits with main process
        ).start()

    def _send_alert_email(self, email, url, status, reason):
        subject = f"[SafeSurf] Alert: {status.upper()} URL detected"
        message = f"""
    Hello,

    You just visited a URL that was classified as *{status.upper()}*.

    URL: {url}
    Reason: {reason}

    Please proceed with caution.

    - SafeSurf Security Team
    """
        try:
            t_alert = time.time()
            send_mail(subject, message, None, [email], fail_silently=False)
            logger.info(f"📧 Alert email sent to {email} in {round(time.time() - t_alert, 4)} sec")
        except Exception as e:
            logger.error(f"❌ Failed to send email to {email}: {str(e)}")


class RedirectAnalyzer(APIView):
    def post(self, request):
        url = request.data.get("url", "").strip()
        if not url:
            return Response({"error": "Missing URL"}, status=400)

        try:
            result = self.analyze_with_selenium(url)
            return Response(result)

        except Exception as e:
            logger.error(f"❌ Unexpected error: {str(e)}")
            return Response({"error": "Internal Server Error"}, status=500)

    def analyze_with_selenium(self, url: str) -> dict:
        # Set up headless Chrome
        options = Options()
        options.headless = True
        options.add_argument('--headless=new')  # New headless mode
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options
        )

        try:
            start_url = url
            driver.get(start_url)

            # Wait a bit to allow redirects to complete (adjust if needed)
            driver.implicitly_wait(5)

            final_url = driver.current_url
            original_domain = urlparse(start_url).netloc
            final_domain = urlparse(final_url).netloc
            is_suspicious = original_domain != final_domain

            return {
                "original_url": start_url,
                "final_url": final_url,
                "redirect_chain": ["Intermediate URLs not tracked via Selenium"],
                "is_suspicious": is_suspicious,
                "reason": "Redirected to different domain" if is_suspicious else "No suspicious redirect"
            }

        except Exception as e:
            return {"error": f"Selenium error: {str(e)}"}

        finally:
            driver.quit()
