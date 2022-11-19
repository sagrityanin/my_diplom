# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import users_list_pb2 as users__list__pb2


class UsersArrayStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.UserList = channel.unary_unary(
                '/UsersArray/UserList',
                request_serializer=users__list__pb2.UsersRequest.SerializeToString,
                response_deserializer=users__list__pb2.UsersResponse.FromString,
                )


class UsersArrayServicer(object):
    """Missing associated documentation comment in .proto file."""

    def UserList(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_UsersArrayServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'UserList': grpc.unary_unary_rpc_method_handler(
                    servicer.UserList,
                    request_deserializer=users__list__pb2.UsersRequest.FromString,
                    response_serializer=users__list__pb2.UsersResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'UsersArray', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class UsersArray(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def UserList(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/UsersArray/UserList',
            users__list__pb2.UsersRequest.SerializeToString,
            users__list__pb2.UsersResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)