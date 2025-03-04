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
    challenge_code = serializers.CharField(
        max_length=255, 
        allow_null=True, 
        required=False,
    )
    device_approval = serializers.BooleanField( 
        required=False,
    )
    mfa_code = serializers.CharField(
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
        if 'mfa_code' in attrs:
            if ('challenge_code' in attrs) or ('device_approval' in attrs):
                raise ValidationError("When entering mfa_code, may not enter challenge_code or device_approval.")
        if 'device_approval' in attrs:
            if ('challenge_code' in attrs) or ('mfa_code' in attrs):
                raise ValidationError("When entering device_approval, may not enter challenge_code or mfa_code.")
        if 'challenge_code' in attrs:
            if any([field in attrs for field in ['mfa_code', 'device_approval', 'username', 'password']]):
                raise ValidationError("When entering challenge code, may not enter mfa_code, device_approval, username, or password.")
        else:
            if ('username' not in attrs) or ('password' not in attrs):
                raise ValidationError("Unless entering challenge_code, you must submit both username and password")
        return attrs
        
