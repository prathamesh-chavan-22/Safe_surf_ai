import threading
import time
import logging
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from .modules.detect_and_expand import is_shortened_url
from .modules.virustotal_checker import scan_url
from .modules.homograph_detector import is_homograph

logger = logging.getLogger(__name__)

class Calculate_Suspicion(APIView):
    def post(self, request):
        start_time = time.time()
        logger.info("▶️ URL Check started")

        url = request.data.get("url")
        user_email = request.data.get("email")

        url = url.strip() if url else None
        if not url or not user_email:
            logger.warning("❌ Missing URL or Email")
            return Response({"error": "Missing URL or Email"}, status=400)

        t1 = time.time()
        count, suspicious_chars = is_homograph(url)
        logger.info(f"🕵️ Checked homograph (original): {round(time.time() - t1, 4)} sec")

        if count > 0:
            shortened, expanded = is_shortened_url(url)
            logger.info(f"🔗 Checked shortening: {shortened}, Expanded: {expanded}")
            threading.Thread(
                target=self.send_alert, args=(user_email, url, "suspicious", "Homograph characters detected")
            ).start()
            return Response({
                "classification": "suspicious",
                "reason": "Detected homograph characters in URL",
                "details": {
                    "Is_shortened": shortened,
                    "Expanded URL": expanded,
                    "Suspicious Characters": suspicious_chars
                }
            })

        t2 = time.time()
        shortened, expanded = is_shortened_url(url)
        logger.info(f"🔗 URL expanded in {round(time.time() - t2, 4)} sec: {expanded}")

        t3 = time.time()
        count, suspicious_chars = is_homograph(expanded)
        logger.info(f"🕵️ Checked homograph (expanded): {round(time.time() - t3, 4)} sec")

        if count > 0:
            threading.Thread(
                target=self.send_alert, args=(user_email, expanded, "suspicious", "Homograph characters detected after expansion")
            ).start()
            return Response({
                "classification": "suspicious",
                "reason": "Detected homograph characters in URL",
                "details": {
                    "Is_shortened": shortened,
                    "Expanded URL": expanded,
                    "Suspicious Characters": suspicious_chars
                }
            })

        t4 = time.time()
        stats = scan_url(expanded)
        logger.info(f"🛡️ VirusTotal scan took: {round(time.time() - t4, 4)} sec")

        classification = "safe"
        reason = ""
        if stats["malicious"] > 0:
            classification = "malicious"
            reason = "Detected as malicious by VirusTotal"
            threading.Thread(target=self.send_alert, args=(user_email, expanded, classification, reason)).start()
        elif stats["suspicious"] > 0:
            classification = "suspicious"
            reason = "Detected as suspicious by VirusTotal"
            threading.Thread(target=self.send_alert, args=(user_email, expanded, classification, reason)).start()

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
            send_mail(
                subject=subject,
                message=message,
                from_email=None,
                recipient_list=[email],
                fail_silently=False
            )
            logger.info(f"📧 Alert email sent to {email}")
        except Exception as e:
            logger.error(f"❌ Failed to send email to {email}: {str(e)}")
