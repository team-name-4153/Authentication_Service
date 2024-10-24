from dataclasses import dataclass

from flask import json

VALIDATE_ERROR = 0
VALIDATE_SUCCESS = 1

@dataclass
class ValidateResult:
    status: int # VALIDATE_ERROR or VALIDATE_SUCCESS
    user_id: str
    message: str
    token: str

    def __init__(self, status=VALIDATE_ERROR, user_id=None, message=None, token=None):
        self.status=status
        self.user_id=user_id
        self.message=message
        self.token=token

    def get_json_result(self):
        status_code = 'success' if (self.status == VALIDATE_SUCCESS) else 'error'
        result = {'status': status_code}
        if self.user_id != None:
            result['user_id'] = self.user_id
        if self.message != None:
            result['message'] = self.message
        if self.token != None:
            result['token'] = self.token
        
        return json.dumps(result)