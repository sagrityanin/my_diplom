from concurrent import futures
import logging
from typing import Tuple
import math
import sjwt

import grpc
from users_list_pb2 import UsersRequest, UsersResponse, PageUsers, Users
import users_list_pb2_grpc
from config import settings
from postgres import connection, cursor


class UsersService(users_list_pb2_grpc.UsersArrayServicer):
    def add_user(self, person, user):
        person.user_id = user["id"]
        person.email = user["email"]

    def UserList(self, request: UsersRequest, context):
        page = self.get_users(request)
        return UsersResponse(users_array=page)

    def get_cout_page(self, request) -> int:
        count_query = f"select count(*) from users where {request.type_notification} = TRUE;"
        cursor.execute(count_query)
        count = cursor.fetchone()
        total_count_page = math.ceil(count[0] / request.page_size)
        print(total_count_page)
        return total_count_page

    def get_users_list(self, request):
        query = f"select id, email from users where {request.type_notification} = TRUE ORDER BY id" \
                f" OFFSET {(request.page_number - 1) * request.page_size} limit {request.page_size};"
        cursor.execute(query)
        users_list = cursor.fetchall()
        print(users_list)
        return users_list

    def get_users(self, request: UsersRequest) -> Tuple[list, int]:
        print(request)
        page = PageUsers()
        if not self.check_role_token(request.access_token):
            page.status = "token broken"
            logging.info(page)
            return page
        page.total_count_page = self.get_cout_page(request)
        print("count_page", page.total_count_page)
        if page.total_count_page < request.page_number:
            page.status = "invalid page params"
            logging.info(page)
            return page
        users_list = self.get_users_list(request)
        for user in users_list:
            self.add_user(page.results.add(), user)
        page.status = "completed"
        logging.info(page)
        return page

    def check_role_token(self, token: str) -> bool:
        payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=token)
        if payload == "Token broken":
            logging.info("Token broken")
            return False
        try:
            if payload["Check_token"] is True and payload["role"] == "admin" \
                    and payload["type"] == "access_token":
                logging.info("Good token")
                return True
        except (KeyError, TypeError):
            logging.info("Token broken")
            return False
        logging.info("Token broken")
        return False


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    users_list_pb2_grpc.add_UsersArrayServicer_to_server(
        UsersService(), server
    )
    server.add_insecure_port("0.0.0.0:50052")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()