from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet, ModelViewSet
from rest_framework.permissions import AllowAny
from user.permission import IsAdminUser, IsLoggedInUserOrAdmin, IsAdminOrAnonymousUser
from user.models import User
from user.serializers import UserSerializer


class PermissionPolicyMixin:
    def check_permissions(self, request):
        try:
            handler = getattr(self, request.method.lower())
        except AttributeError:
            handler = None

        if (
            handler
            and self.permission_classes_per_method
            and self.permission_classes_per_method.get(handler.__name__)
        ):
            self.permission_classes = self.permission_classes_per_method.get(handler.__name__)

        super().check_permissions(request)


class UserViewSet(PermissionPolicyMixin, ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes_per_method = {
        
        "create": [IsAdminUser],
        "list": [IsAdminOrAnonymousUser]
    }

    # def get_permissions(self):
    #     permission_classes = []
    #     if self.action == 'create':
    #         permission_classes = [IsAdminUser]
    #     elif self.action == 'list':
    #         permission_classes = [IsAdminOrAnonymousUser]
    #     elif self.action == 'retrieve' or self.action == 'update' or self.action == 'partial_update':
    #         permission_classes = [IsLoggedInUserOrAdmin]
    #     elif self.action == 'destroy':
    #         permission_classes = [IsLoggedInUserOrAdmin]
    #     return [permission() for permission in permission_classes]      



class LoginView(ViewSet):
    serializer_class = AuthTokenSerializer

    def create(sself, request):
        return ObtainAuthToken().post(request)


class LogoutView(APIView):
    def get(self, request, format=None):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)
