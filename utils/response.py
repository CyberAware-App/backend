class ResponseMixin:
    @staticmethod
    def success_response(data=None, message="Success", status="success"):
        return {
            "status": status,
            "message": message,
            "data": data
        }

    @staticmethod
    def error_response(errors=None, message="Error", status="error"):
        return {
            "status": status,
            "message": message,
            "errors": errors
        } 