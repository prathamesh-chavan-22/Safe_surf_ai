from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .modules.detect_and_expand import is_shortened_url
from .modules.virustotal_checker import scan_url

class Calculate_Suspicion(APIView):
    def post(self, request):
        print(request.data)
        url = request.data.get("url")
        url = url.strip() if url else None  # Ensure URL is not None and strip whitespace
        if not url:
            return Response({"error": "Missing URL"}, status=400)

        # Expand URL if shortened
        shortened, expanded = is_shortened_url(url)

        stats = scan_url(expanded)

        data = {
            "Is_shortened": shortened,
            "Expanded URL": expanded,
        }

        if stats["malicious"] > 0:
            classification = "malicious"
            reason = "Detected as malicious by VirusTotal"
        elif stats["suspicious"] > 0:
            classification = "suspicious"
            reason = "Detected as suspicious by VirusTotal"
        else:
            classification = "safe"

        


        return Response({
            "classification": classification,
            "reason": reason,
            "details": data
        })
