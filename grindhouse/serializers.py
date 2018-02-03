import uuid

from rehive import Rehive, APIException
from rest_framework import serializers
from django.db import transaction

from grindhouse.models import Company, User, Currency, ServiceAccount


class ActivateSerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)
    identifier = serializers.CharField(read_only=True)
    name = serializers.CharField(read_only=True)
    secret = serializers.UUIDField(read_only=True)

    def validate(self, validated_data):
        rehive = Rehive(validated_data.get('token'))

        try:
            user = rehive.user.get()
            groups = [g['name'] for g in user['groups']]
            if len(set(["admin", "service"]).intersection(groups)) <= 0:
                raise serializers.ValidationError(
                    {"token": ["Invalid admin user."]})
        except APIException:
            raise serializers.ValidationError({"token": ["Invalid user."]})

        try:
            company = rehive.admin.company.get()
        except APIException:
            raise serializers.ValidationError({"token": ["Invalid company."]})

        if Company.objects.filter(identifier=company['identifier']).exists():
            raise serializers.ValidationError(
                {"token": ["Company already activated."]})

        try:
            currencies = rehive.company.currencies.get()
        except APIException:
            raise serializers.ValidationError({"non_field_errors":
                ["Unkown error."]})

        validated_data['user'] = user
        validated_data['company'] = company
        validated_data['currencies'] = currencies

        return validated_data

    def create(self, validated_data):
        token = validated_data.get('token')
        rehive_user = validated_data.get('user')
        rehive_company = validated_data.get('company')
        currencies = validated_data.get('currencies')

        with transaction.atomic():
            user = User.objects.create(token=token,
                identifier=uuid.UUID(rehive_user['identifier']).hex)

            company = Company.objects.create(admin=user,
                identifier=rehive_company.get('identifier'),
                name=rehive_company.get('name'))

            user.company = company
            user.save()

            # Add currencies to company automatically.
            for kwargs in currencies:
                kwargs['company'] = company
                currency = Currency.objects.create(**kwargs)

            serviceaccount, created = ServiceAccount.objects.get_or_create(
                token=token,
                company=rehive_company.get('identifier')
            )

            serviceaccount.active = True
            serviceaccount.save()

            return company

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(write_only=True, required=True, allow_blank=False)
    password = serializers.CharField(write_only=True, style={"input_type": "password"}, required=True, allow_blank=False)

    def create(self, validated_data):
        company_identifier = 'grindhouse'
        email = validated_data.get("email")
        password = validated_data.get("password")
        service = ServiceAccount.objects.get(company=company_identifier)
        rehive = Rehive(service.token)

        response = rehive.auth.login(
            user=email,
            company=company_identifier,
            password=password
        )

        self.context['request'].session.get('auth_token', response['data']['token'])
        return response


class DeactivateSerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)

    def validate(self, validated_data):
        rehive = Rehive(validated_data.get('token'))

        try:
            user = rehive.user.get()
            groups = [g['name'] for g in user['groups']]
            if len(set(["admin", "service"]).intersection(groups)) <= 0:
                raise serializers.ValidationError(
                    {"token": ["Invalid admin user."]})
        except APIException:
            raise serializers.ValidationError({"token": ["Invalid user."]})

        try:
            validated_data['company'] = Company.objects.get(
                identifier=user['company'])
        except Company.DoesNotExist:
            raise serializers.ValidationError(
                {"token": ["Company has not been activated yet."]})

        return validated_data

    def delete(self):
        # Cascade delete to rmeove the company and other children entities.
        self.validated_data['company'].admin.delete()


class AdminCompanySerializer(serializers.ModelSerializer):
    identifier = serializers.CharField(read_only=True)
    secret = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True)

    class Meta:
        model = Company
        fields = ('identifier', 'secret', 'name',)


class CurrencySerializer(serializers.ModelSerializer):

    class Meta:
        model = Currency
        fields = (
            'code', 'description', 'symbol', 'unit', 'divisibility', 'enabled',
        )
