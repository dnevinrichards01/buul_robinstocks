from django.core.exceptions import ValidationError
from rest_framework import serializers

class ConnectRobinhoodLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, allow_null=True)
    password = serializers.CharField(max_length=255, allow_null=True)
    challenge_code = serializers.CharField(max_length=255, allow_null=True)
    mfa_code = serializers.CharField(max_length=255, allow_null=True)
    by_sms = serializers.BooleanField(default=True, allow_null=True)

