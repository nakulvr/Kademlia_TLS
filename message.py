from collections import OrderedDict

# a message queue to manage all pending requests
class Messages:
    mQueue = OrderedDict()

    # insert the request based on the nonce
    def insertRequest(self, nonce):
        Messages.mQueue[nonce] = None

    # remove the request
    def removeRequest(self, nonce):
        Messages.mQueue.pop(nonce)

    # insert the response corresponding to the nonce value
    def insertResponse(self, nonce, response):
        Messages.mQueue[nonce] = response

    # check for the nonce in the message queue
    def checkResponse(self, nonce):
        return nonce in Messages.mQueue.keys()

    # return the response based on the nonce
    def returnResponse(self, nonce):
        return Messages.mQueue[nonce]


