from django.shortcuts import render
from django.rest_framework.views import APIView
from django.rest_framework.response import Response


class CheckUrlView(APIView):
    """
    View to check if a URL is safe.
    """

    def post(self, request):
        url = request.data.get('url')
        print(f"Received URL: {url}")  # Debugging line to check the received URL
        if not url:
            return Response({'error': 'URL is required'}, status=400)

        # Here you would implement the logic to check the URL's safety.
        # For now, we will just return a dummy response.
        is_safe = True  # Replace with actual safety check logic

        return Response({'url': url, 'is_safe': is_safe})

