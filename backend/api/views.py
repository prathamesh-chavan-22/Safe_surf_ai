from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from .modules.detect_and_expand import is_shortened_url
from .modules.virustotal_checker import scan_url
from .modules.homograph_detector import is_homograph


class Calculate_Suspicion(APIView):
    def post(self, request):
        print(request.data)
        url = request.data.get("url")
        user_email = request.data.get("email")  # ✅ Accept user email

        url = url.strip() if url else None
        if not url or not user_email:
            return Response({"error": "Missing URL or Email"}, status=400)

        # Precheck for homograph characters
        count, suspicious_chars = is_homograph(url)
        if count > 0:
            shortened, expanded = is_shortened_url(url)
            self.send_alert(user_email, url, "suspicious", "Homograph characters detected")
            return Response({
                "classification": "suspicious",
                "reason": "Detected homograph characters in URL",
                "details": {
                    "Is_shortened": shortened,
                    "Expanded URL": expanded,
                    "Suspicious Characters": suspicious_chars
                }
            })

        # Expand URL if shortened
        shortened, expanded = is_shortened_url(url)

        # Check again after expansion
        count, suspicious_chars = is_homograph(expanded)
        if count > 0:
            self.send_alert(user_email, expanded, "suspicious", "Homograph characters detected after expansion")
            return Response({
                "classification": "suspicious",
                "reason": "Detected homograph characters in URL",
                "details": {
                    "Is_shortened": shortened,
                    "Expanded URL": expanded,
                    "Suspicious Characters": suspicious_chars
                }
            })

        stats = scan_url(expanded)

        classification = "safe"
        reason = ""
        if stats["malicious"] > 0:
            classification = "malicious"
            reason = "Detected as malicious by VirusTotal"
            self.send_alert(user_email, expanded, classification, reason)

        elif stats["suspicious"] > 0:
            classification = "suspicious"
            reason = "Detected as suspicious by VirusTotal"
            self.send_alert(user_email, expanded, classification, reason)

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
        send_mail(
            subject=subject,
            message=message,
            from_email=None,  # uses DEFAULT_FROM_EMAIL from settings.py
            recipient_list=[email],
            fail_silently=False
        )
