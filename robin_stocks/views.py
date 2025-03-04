from rest_framework.permissions import IsAuthenticated, AllowAny
from django.http import HttpResponseBadRequest, HttpResponse, JsonResponse
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from .serializers import ConnectRobinhoodLoginSerializer
from django.db import transaction
from functools import partial
from .tasks import login_robinhood
from .robinhood import check_device_approvals
from django.core.cache import cache
import json
from rest_framework.exceptions import ValidationError

class ConnectRobinhoodView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        import pdb
        breakpoint() 
        serializer = ConnectRobinhoodLoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            if "non_field_errors" in e.detail and len(e.detail[field]) > 0:
                return JsonResponse(
                    {
                        "success": None, 
                        "error": e.detail["non_field_errors"][0]
                    }, 
                    status=400
                )
            for field in e.detail:
                error_messages = {}
                if field in e.detail and len(e.detail[field]) > 0:
                    error_messages[field] = e.detail[field][0]
                return JsonResponse(
                    {
                        "success": None, 
                        "error": error_messages
                    }, 
                    status=200
                )
            return JsonResponse(
                {
                    "success": None, 
                    "error": f"error: {str(e)}"
                }, 
                status=400
            )
        except Exception as e:
            return JsonResponse(
                {
                    "success": None, 
                    "error": f"error: {str(e)}"
                }, 
                status=400
            )
        
        validated_data = serializer.validated_data
        uid = self.request.user.id
        validated_data['uid'] = uid
        login_robinhood.apply_async(kwargs=validated_data)

        return JsonResponse(
            {
                "success": "recieved",
                "error": None
            }, 
            status=201
        )
    
    def get(self, request, *args, **kwargs):
        uid = self.request.user.id
        # import pdb 
        # breakpoint()
        challenge = cache.get(f"uid_{uid}_rh_challenge")
        if not challenge:
            return JsonResponse(
                {
                    "success": None,
                    "error": None
                }, 
                status=201
            )
        
        challenge_data = json.loads(challenge)
        if challenge_data["success"]:
            return JsonResponse(
                {
                    "success": challenge_data["success"],
                    "error": None
                }, 
                status=201
            )
        elif not challenge_data["challenge_type"]:
            return JsonResponse(
                {
                    "success": None,
                    "error": {
                        "challenge_type": challenge_data["challenge_type"],
                        "error_message": challenge_data["error"]
                    }
                }, 
                status=400
            )
        else:
            return JsonResponse(
                {
                    "success": None,
                    "error": {
                        "challenge_type": challenge_data["challenge_type"],
                        "error_message": challenge_data["error"]
                    }
                }, 
                status=201
            )


        

        # challenge_data = json.loads(challenge)
        # if challenge_data['challenge_type'] == 'device_approvals':
            # check_device_approvals(uid)
            # challenge_updated = cache.get(f"uid_{uid}_rh_challenge")
            # if challenge_updated:
            #     challenge_data_updated = json.loads(challenge_updated)
            #     return...
            # else:
            #     return JsonResponse(
            #         {
            #             "success": None,
            #             "error": None
            #         }, 
            #         status=201
            #     )

        # return JsonResponse(data, status=201)
    