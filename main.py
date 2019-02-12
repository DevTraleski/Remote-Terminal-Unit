from coapthon.server.coap import CoAP
from coapthon.resources.resource import Resource

class Info(Resource):
    def __init__(self, name="Info", coap_server=None):
        super(Info, self).__init__(name, coap_server, visible=True,
                                    observable=True, allow_children=True)
        self.payload = "12.4"

    def render_GET(self, request):
        
        return self

class CoAPServer(CoAP):
    def __init__(self, host, port, multicast):
        CoAP.__init__(self, (host, port), multicast)
        self.add_resource('info/', Info())

def main():
    server = CoAPServer("224.0.1.187", 5001, True)
    try:
        server.listen(10)
    except KeyboardInterrupt:
        print ("Server Shutdown")
        server.close()
        print("Exiting...")

if __name__ == '__main__':
    main()
