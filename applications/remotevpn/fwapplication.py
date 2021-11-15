import sys
import json

class FwApplication():
    def __init__(self):
        """Constructor method"""

        args_len = len(sys.argv)
        if args_len < 2 or args_len > 3:
            raise Exception(f'method and params parameters are required')

        method_name = sys.argv[1]

        if args_len == 3:
            params = sys.argv[2]
        else:
            params = None

        api_func = getattr(self, method_name, None)

        if not api_func:
            raise Exception(f'method is not supported')


        if params:
            params = json.loads(params)
            return api_func(params)

        return api_func()

    def log(txt):
        print(txt)

    def log_err(err_msg):
        print(err_msg, file=sys.stderr)