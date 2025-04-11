from django.db import models
# from django.contrib.auth.models import User
from api.models import User
from django.utils.timezone import now
from accumate_backend.settings import RH_ACCESS_KMS_ALIAS, \
    RH_REFRESH_KMS_ALIAS, PLAID_ITEM_KMS_ALIAS, PLAID_USER_KMS_ALIAS, \
    USER_PII_KMS_ALIAS

class UserRobinhoodInfo(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token_type = models.CharField(max_length=255) 
    access_token = models.CharField(max_length=2000) #bin
    access_token_dek = models.BinaryField()
    refresh_token = models.CharField(max_length=255) #bin
    device_token = models.CharField(max_length=255) #bin
    refresh_token_device_dek = models.BinaryField()
    issued_time = models.DateTimeField(default=now)
    # adding this in a later migration, so need to make it nullable for hypothetical existing rows...
    expiration_time = models.DateTimeField(null=True) 

    def refresh(self):
        from robin_stocks.robinhood import refresh, create_session
        refresh(create_session(), self.user.id)

class Log(models.Model):
    name = models.CharField()
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING, 
                             null=True, default=None,
                             related_name='rh_logs')
    date = models.DateTimeField(auto_now=True)
    args = models.JSONField()
    response = models.JSONField()
    status = models.IntegerField()
    success = models.BooleanField()

    class Meta:
        indexes = [
            models.Index(fields=['date', 'success', 'status']),
            models.Index(fields=['user', 'date', 'success', 'status'])
        ]


