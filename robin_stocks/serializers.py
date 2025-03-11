from django.core.exceptions import ValidationError
from rest_framework import serializers

class ConnectRobinhoodLoginSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=255, 
        allow_null=True,
        required=False,
    )
    password = serializers.CharField(
        max_length=255, 
        allow_null=True,
        required=False,
    )
    sms = serializers.CharField(
        max_length=255, 
        allow_null=True, 
        required=False,
    )
    prompt = serializers.BooleanField( 
        required=False,
    )
    app = serializers.CharField(
        max_length=255, 
        allow_null=True, 
        required=False,
    )
    by_sms = serializers.BooleanField(
        allow_null=True, 
        required=False,
        default=True
    )

    def validate(self, attrs):
        if len([mfa in attrs for mfa in ['app', 'sms', 'prompt']]) > 1:
            raise ValidationError("You may only choose one mfa method.")
        if ('username' not in attrs) or ('password' not in attrs):
            raise ValidationError("You must submit both username and password")
        return attrs
        
