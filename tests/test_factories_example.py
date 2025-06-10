"""
Example tests demonstrating how to use the factories module effectively.

This file shows various patterns for using factory-boy factories
to create test data efficiently.
"""

import pytest
from uuid import uuid4

from tests.factories import (
    UserFactory, VerifiedUserFactory, AdminUserFactory,
    LinkedAccountFactory, GoogleLinkedAccountFactory,
    RoleFactory, AdminRoleFactory, UserManagerRoleFactory, ViewerRoleFactory,
    PermissionFactory, UserPermissionFactory, AdminPermissionFactory,
    UserRoleFactory, RolePermissionFactory,
    create_user_create_schema, create_multiple_users,
    create_complete_oauth_scenario, create_sso_test_scenario, create_rbac_test_scenario,
    create_standard_permissions, create_standard_roles
)


class TestFactoryBasics:
    """Test basic factory usage patterns."""

    def test_user_factory_build(self):
        """Test building user instances without database persistence."""
        # Build single user
        user = UserFactory.build()
        
        assert user.email is not None
        assert "@example.com" in user.email
        assert user.name is not None
        assert user.is_active is True
        assert user.is_verified is False
        assert user.is_deleted is False

    def test_user_factory_with_overrides(self):
        """Test building user with custom values."""
        user = UserFactory.build(
            email="custom@test.com",
            name="Custom User",
            is_verified=True
        )
        
        assert user.email == "custom@test.com"
        assert user.name == "Custom User"
        assert user.is_verified is True

    def test_multiple_users_batch_creation(self):
        """Test creating multiple users at once."""
        users = create_multiple_users(count=3, is_verified=True)
        
        assert len(users) == 3
        for user in users:
            assert user.is_verified is True
            assert user.email is not None

    def test_specialized_user_factories(self):
        """Test specialized user factory classes."""
        # Verified user
        verified_user = VerifiedUserFactory.build()
        assert verified_user.is_verified is True
        
        # Admin user
        admin_user = AdminUserFactory.build()
        assert admin_user.is_verified is True
        assert "admin" in admin_user.email


class TestLinkedAccountFactories:
    """Test linked account factory patterns."""

    def test_linked_account_factory(self):
        """Test basic linked account creation."""
        account = LinkedAccountFactory.build()
        
        assert account.provider in ["google", "facebook", "github", "twitter"]
        assert account.given_name is not None
        assert account.family_name is not None
        assert account.email is not None
        assert account.sub is not None

    def test_google_linked_account_factory(self):
        """Test Google-specific linked account."""
        account = GoogleLinkedAccountFactory.build()
        
        assert account.provider == "google"
        assert "google-" in account.sub
        assert "@gmail.com" in account.email

    def test_linked_account_with_user_id(self):
        """Test linking account to specific user."""
        user_id = uuid4()
        account = LinkedAccountFactory.build(user_id=user_id)
        
        assert account.user_id == user_id


class TestRoleAndPermissionFactories:
    """Test role and permission factory patterns."""

    def test_role_factory(self):
        """Test basic role creation."""
        role = RoleFactory.build()
        
        assert role.name is not None
        assert role.description is not None

    def test_specialized_role_factories(self):
        """Test specialized role factories."""
        admin_role = AdminRoleFactory.build()
        assert admin_role.name == "admin"
        
        manager_role = UserManagerRoleFactory.build()
        assert manager_role.name == "user_manager"
        
        viewer_role = ViewerRoleFactory.build()
        assert viewer_role.name == "viewer"

    def test_permission_factory(self):
        """Test basic permission creation."""
        permission = PermissionFactory.build()
        
        assert permission.name is not None
        assert ":" in permission.name  # Should have HTTP method and path
        assert permission.description is not None

    def test_specialized_permission_factories(self):
        """Test specialized permission factories."""
        user_perm = UserPermissionFactory.build()
        assert "/api/v1/users" in user_perm.name
        
        admin_perm = AdminPermissionFactory.build()
        assert "/api/v1/admin/" in admin_perm.name


class TestSchemaFactories:
    """Test schema creation helpers."""

    def test_user_create_schema(self):
        """Test UserCreate schema generation."""
        user_schema = create_user_create_schema(
            email="test@example.com",
            name="Test User"
        )
        
        assert user_schema.email == "test@example.com"
        assert user_schema.name == "Test User"
        assert user_schema.password is not None

    def test_user_create_schema_with_defaults(self):
        """Test UserCreate schema with default values."""
        user_schema = create_user_create_schema()
        
        assert user_schema.email is not None
        assert user_schema.name is not None
        assert user_schema.password == "testpassword123"


class TestComplexScenarios:
    """Test complex multi-model scenarios."""

    def test_complete_oauth_scenario(self):
        """Test complete OAuth scenario creation."""
        scenario = create_complete_oauth_scenario()
        
        # Check all components are present
        assert "users" in scenario
        assert "admin_user" in scenario
        assert "manager_user" in scenario
        assert "regular_user" in scenario
        assert "roles" in scenario
        assert "permissions" in scenario
        assert "linked_accounts" in scenario
        assert "user_roles" in scenario
        assert "role_permissions" in scenario
        
        # Check data integrity
        assert len(scenario["users"]) == 3
        assert len(scenario["roles"]) == 4  # admin, user_manager, viewer, editor
        assert len(scenario["permissions"]) > 0
        assert len(scenario["user_roles"]) == 3
        assert len(scenario["role_permissions"]) > 0

    def test_sso_test_scenario(self):
        """Test SSO-focused scenario creation."""
        scenario = create_sso_test_scenario()
        
        # Check SSO-specific components
        assert "google_user" in scenario
        assert "facebook_user" in scenario
        assert "regular_user" in scenario
        assert "multi_provider_user" in scenario
        assert "linked_accounts" in scenario
        
        # Check SSO data characteristics
        assert scenario["google_user"].is_verified is True
        assert scenario["facebook_user"].is_verified is True
        assert scenario["regular_user"].is_verified is False
        assert len(scenario["linked_accounts"]) == 4

    def test_rbac_test_scenario(self):
        """Test RBAC-focused scenario creation."""
        scenario = create_rbac_test_scenario()
        
        # Check RBAC components
        assert "roles" in scenario
        assert "permissions" in scenario
        assert "users" in scenario
        assert "super_admin" in scenario
        assert "department_admin" in scenario
        assert "team_lead" in scenario
        assert "employee" in scenario
        
        # Check hierarchical structure
        assert len(scenario["roles"]) == 4
        assert len(scenario["permissions"]) > 0
        assert len(scenario["users"]) == 4

    def test_standard_permissions_and_roles(self):
        """Test standard permission and role sets."""
        permissions = create_standard_permissions()
        roles = create_standard_roles()
        
        # Check standard permissions
        assert len(permissions) == 12  # 4 user + 4 role + 4 permission operations
        permission_names = [p.name for p in permissions]
        assert "GET:/api/v1/users" in permission_names
        assert "POST:/api/v1/admin/roles" in permission_names
        
        # Check standard roles
        assert len(roles) == 4
        role_names = [r.name for r in roles]
        assert "admin" in role_names
        assert "user_manager" in role_names
        assert "viewer" in role_names
        assert "editor" in role_names


@pytest.mark.asyncio
class TestFactoryIntegrationWithDatabase:
    """Test factories working with actual database operations."""

    async def test_create_user_with_factory_data(self, user_service):
        """Test creating database user with factory-generated data."""
        user_create = create_user_create_schema(
            email="factory@example.com",
            name="Factory User"
        )
        
        user = await user_service.create_user(user_create)
        
        assert user.id is not None
        assert user.email == "factory@example.com"
        assert user.name == "Factory User"

    async def test_factory_with_service_fixtures(self, user_service, role_service, rbac_service):
        """Test using factories with multiple service fixtures."""
        # Create user using factory
        user_create = create_user_create_schema()
        user = await user_service.create_user(user_create)
        
        # Create role using factory
        role = AdminRoleFactory.build()
        created_role = await role_service.create_role({
            "name": role.name,
            "description": role.description
        })
        
        # Assign role to user
        user_role = await rbac_service.assign_role_to_user(
            str(user.id), 
            str(created_role.id)
        )
        
        assert user_role is not None
        assert user_role.user_id == user.id
        assert user_role.role_id == created_role.id


class TestFactoryCustomization:
    """Test advanced factory customization patterns."""

    def test_factory_with_lazy_attributes(self):
        """Test factories with computed attributes."""
        user = UserFactory.build()
        
        # Test that lazy functions generate unique values
        user2 = UserFactory.build()
        assert user.id != user2.id
        assert user.email != user2.email

    def test_factory_sequence_attributes(self):
        """Test factories with sequence-based attributes."""
        users = [UserFactory.build() for _ in range(3)]
        
        emails = [user.email for user in users]
        # Should have user0@, user1@, user2@ pattern
        assert all("user" in email for email in emails)
        assert len(set(emails)) == 3  # All unique

    def test_factory_fuzzy_choices(self):
        """Test factories with fuzzy choice attributes."""
        accounts = [LinkedAccountFactory.build() for _ in range(10)]
        
        providers = [account.provider for account in accounts]
        expected_providers = ["google", "facebook", "github", "twitter"]
        
        # Should only use expected providers
        assert all(provider in expected_providers for provider in providers)

    def test_factory_with_related_objects(self):
        """Test creating related objects with factories."""
        user = UserFactory.build()
        
        # Create linked account for the user
        linked_account = LinkedAccountFactory.build(user_id=user.id)
        
        assert linked_account.user_id == user.id
        
        # Create role assignment
        role = RoleFactory.build()
        user_role = UserRoleFactory.build(user_id=user.id, role_id=role.id)
        
        assert user_role.user_id == user.id
        assert user_role.role_id == role.id


class TestFactoryPerformance:
    """Test factory performance and efficiency."""

    def test_bulk_creation_performance(self):
        """Test creating large amounts of test data efficiently."""
        # This should be fast since we're just building objects
        users = [UserFactory.build() for _ in range(100)]
        roles = [RoleFactory.build() for _ in range(20)]
        permissions = [PermissionFactory.build() for _ in range(50)]
        
        assert len(users) == 100
        assert len(roles) == 20
        assert len(permissions) == 50
        
        # Check uniqueness
        user_emails = [user.email for user in users]
        assert len(set(user_emails)) == 100  # All unique

    def test_scenario_creation_efficiency(self):
        """Test that complex scenarios are created efficiently."""
        # Should be able to create complex scenarios quickly
        scenarios = [create_complete_oauth_scenario() for _ in range(5)]
        
        assert len(scenarios) == 5
        
        # Each scenario should be independent
        user_emails = []
        for scenario in scenarios:
            for user in scenario["users"]:
                user_emails.append(user.email)
        
        # Should have unique emails across all scenarios
        assert len(set(user_emails)) == len(user_emails) 