from rest_framework.permissions import IsAuthenticated, AllowAny
from django.http import HttpResponseBadRequest, HttpResponse, JsonResponse
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from .serializers import ConnectRobinhoodLoginSerializer
from django.db import transaction
from functools import partial
from .tasks import login_robinhood
from django.core.cache import cache
import json

class ConnectRobinhoodView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Use the serializer to validate input data
        serializer = ConnectRobinhoodLoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            return HttpResponseBadRequest(e, status=400)
        # Access the validated data
        validated_data = serializer.validated_data
        uid = self.request.user.id
        validated_data['uid'] = uid
        result = transaction.on_commit(
            partial(
                login_robinhood.apply_async,
                kwargs=validated_data
            )
        )
        return HttpResponse("Recieved", status=201)
    
    def get(self, request, *args, **kwargs):
        uid = self.request.user.id
        challenge = cache.get(f"uid_{uid}_challenge")
        if challenge:
            data = json.loads(challenge)
        else:
            data = {"message": "no updates"}
        return JsonResponse(data, status=201)