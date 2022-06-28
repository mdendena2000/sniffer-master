
class HTTP:

    def __init__(self, data):
        try:
            self.data = data.decode('utf-8')
        except:
            self.data = data
