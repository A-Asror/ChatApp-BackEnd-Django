from django.contrib import admin
from .models import CustomUser, Jwt, Favorite, UserProfile, GenericFileUpload


admin.site.register((CustomUser, Jwt, Favorite, UserProfile, GenericFileUpload))