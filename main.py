from coapthon.server.coap import CoAP
from coapthon.resources.resource import Resource
from exampleresources import BasicResource

class CoAPServer(CoAP):
    def __init__(self, host, port, multicast):
        CoAP.__init__(self, (host, port), multicast=mu√ltiast)
        self.add_resource('basic/', BasicResource())

def main():
    server = CoAPServer("224.0.0.0", 5683, True)
    try:
        server.listen(10)
    except KeyboardInterrupt:
        print ("Server Shutdown")
        server.close()
        print("Exiting...")

if __name__ == '__main__':
    main()

class BasicResource(Resource):
    def __init__(self, name="BasicResource", coap_server=None):
        super(BasicResource, self).__init__(name, coap_server, visible=True,
                                            observable=True, allow_children=True)
        self.payload = "Basic Resource"

    def render_GET(self, request):
        return self

    def render_PUT(self, request):
        self.payload = request.payload
        return self

    def render_POST(self, request):
        res = BasicResource()
        res.location_query = request.uri_query
        res.payload = request.payload
        return res

    def render_DELETE(self, request):
        return True
