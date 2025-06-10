"""
Factory classes for creating test data.

This module provides factory classes using factory-boy to create test instances
of our OAuth2 service models with realistic fake data.
"""

from datetime import datetime
from typing import Any, Dict, List
from uuid import uuid4

import factory
from factory import fuzzy
from faker import Faker

from app.users.models import User, LinkedAccount
from app.rbac.models import Role, Permission, UserRole, RolePermission
from app.users.schemas import UserCreate, UserUpdate, LinkedAccountCreate
from app.rbac.schemas import RoleCreate, RoleUpdate, PermissionCreate, PermissionUpdate

fake = Faker()


class UserFactory(factory.Factory):
    """Factory for creating User instances."""
    
    class Meta:
        model = User
    
    id = factory.LazyFunction(uuid4)
    email = factory.Sequence(lambda n: f"user{n}@example.com")
    name = factory.Faker("name")
    password = factory.LazyFunction(lambda: fake.password(length=12))
    is_active = True
    is_verified = False
    is_deleted = False
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)


class VerifiedUserFactory(UserFactory):
    """Factory for creating verified User instances."""
    
    is_verified = True


class AdminUserFactory(UserFactory):
    """Factory for creating admin User instances."""
    
    email = factory.Sequence(lambda n: f"admin{n}@example.com")
    name = factory.Faker("name")
    is_verified = True


class LinkedAccountFactory(factory.Factory):
    """Factory for creating LinkedAccount instances."""
    
    class Meta:
        model = LinkedAccount
    
    id = factory.LazyFunction(uuid4)
    user_id = factory.LazyFunction(uuid4)
    provider = fuzzy.FuzzyChoice(["google", "facebook", "github", "twitter"])
    given_name = factory.Faker("first_name")
    family_name = factory.Faker("last_name")
    picture = factory.Faker("image_url")
    email = factory.LazyAttribute(lambda obj: f"{obj.given_name.lower()}.{obj.family_name.lower()}@gmail.com")
    sub = factory.LazyFunction(lambda: f"oauth-{fake.uuid4()}")
    is_verified = True
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)


class GoogleLinkedAccountFactory(LinkedAccountFactory):
    """Factory for creating Google LinkedAccount instances."""
    
    provider = "google"
    email = factory.Sequence(lambda n: f"googleuser{n}@gmail.com")
    sub = factory.LazyFunction(lambda: f"google-{fake.random_number(digits=21)}")


class RoleFactory(factory.Factory):
    """Factory for creating Role instances."""
    
    class Meta:
        model = Role
    
    id = factory.LazyFunction(uuid4)
    name = factory.LazyFunction(lambda: fake.job().lower().replace(" ", "_"))
    description = factory.Faker("sentence", nb_words=6)
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)


class AdminRoleFactory(RoleFactory):
    """Factory for creating admin Role instances."""
    
    name = "admin"
    description = "Administrator with full system access"


class UserManagerRoleFactory(RoleFactory):
    """Factory for creating user manager Role instances."""
    
    name = "user_manager"
    description = "Can manage users but not system roles"


class ViewerRoleFactory(RoleFactory):
    """Factory for creating viewer Role instances."""
    
    name = "viewer"
    description = "Read-only access to resources"


class PermissionFactory(factory.Factory):
    """Factory for creating Permission instances."""
    
    class Meta:
        model = Permission
    
    id = factory.LazyFunction(uuid4)
    name = factory.LazyFunction(
        lambda: f"{fake.random_element(['GET', 'POST', 'PUT', 'DELETE'])}:/api/v1/{fake.word()}"
    )
    description = factory.Faker("sentence", nb_words=4)
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)


class UserPermissionFactory(PermissionFactory):
    """Factory for creating user-related Permission instances."""
    
    name = factory.LazyFunction(
        lambda: f"{fake.random_element(['GET', 'POST', 'PUT', 'DELETE'])}:/api/v1/users"
    )
    description = "User management permission"


class AdminPermissionFactory(PermissionFactory):
    """Factory for creating admin-related Permission instances."""
    
    name = factory.LazyFunction(
        lambda: f"{fake.random_element(['GET', 'POST', 'PUT', 'DELETE'])}:/api/v1/admin/{fake.word()}"
    )
    description = "Administrative permission"


class UserRoleFactory(factory.Factory):
    """Factory for creating UserRole instances."""
    
    class Meta:
        model = UserRole
    
    id = factory.LazyFunction(uuid4)
    user_id = factory.LazyFunction(uuid4)
    role_id = factory.LazyFunction(uuid4)
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)


class RolePermissionFactory(factory.Factory):
    """Factory for creating RolePermission instances."""
    
    class Meta:
        model = RolePermission
    
    id = factory.LazyFunction(uuid4)
    role_id = factory.LazyFunction(uuid4)
    permission_id = factory.LazyFunction(uuid4)
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)


# Helper functions for creating schema data

def create_user_data(**kwargs) -> Dict[str, Any]:
    """Create user data dictionary for API requests."""
    data = {
        "email": fake.email(),
        "name": fake.name(),
        "password": "testpassword123",
    }
    data.update(kwargs)
    return data


def create_user_create_schema(**kwargs) -> UserCreate:
    """Create UserCreate schema instance."""
    data = create_user_data(**kwargs)
    return UserCreate(**data)


def create_user_update_schema(**kwargs) -> UserUpdate:
    """Create UserUpdate schema instance."""
    data = {
        "name": fake.name(),
    }
    data.update(kwargs)
    return UserUpdate(**data)


def create_linked_account_data(**kwargs) -> Dict[str, Any]:
    """Create linked account data dictionary for API requests."""
    data = {
        "provider": "google",
        "given_name": fake.first_name(),
        "family_name": fake.last_name(),
        "picture": fake.image_url(),
        "email": fake.email(),
    }
    data.update(kwargs)
    return data


def create_linked_account_create_schema(**kwargs) -> LinkedAccountCreate:
    """Create LinkedAccountCreate schema instance."""
    data = create_linked_account_data(**kwargs)
    # Add default sub if not provided
    if 'sub' not in data:
        data['sub'] = f"oauth-{fake.uuid4()}"
    # Add default is_verified if not provided  
    if 'is_verified' not in data:
        data['is_verified'] = True
    return LinkedAccountCreate(**data)


def create_role_data(**kwargs) -> Dict[str, Any]:
    """Create role data dictionary for API requests."""
    data = {
        "name": fake.job().lower().replace(" ", "_"),
        "description": fake.sentence(nb_words=6),
    }
    data.update(kwargs)
    return data


def create_role_create_schema(**kwargs) -> RoleCreate:
    """Create RoleCreate schema instance."""
    data = create_role_data(**kwargs)
    return RoleCreate(**data)


def create_role_update_schema(**kwargs) -> RoleUpdate:
    """Create RoleUpdate schema instance."""
    data = {
        "name": fake.job().lower().replace(" ", "_"),
        "description": fake.sentence(nb_words=6),
    }
    data.update(kwargs)
    return RoleUpdate(**data)


def create_permission_data(**kwargs) -> Dict[str, Any]:
    """Create permission data dictionary for API requests."""
    data = {
        "name": f"{fake.random_element(['GET', 'POST', 'PUT', 'DELETE'])}:/api/v1/{fake.word()}",
        "description": fake.sentence(nb_words=4),
    }
    data.update(kwargs)
    return data


def create_permission_create_schema(**kwargs) -> PermissionCreate:
    """Create PermissionCreate schema instance."""
    data = create_permission_data(**kwargs)
    return PermissionCreate(**data)


def create_permission_update_schema(**kwargs) -> PermissionUpdate:
    """Create PermissionUpdate schema instance."""
    data = {
        "name": f"{fake.random_element(['GET', 'POST', 'PUT', 'DELETE'])}:/api/v1/{fake.word()}",
        "description": fake.sentence(nb_words=4),
    }
    data.update(kwargs)
    return PermissionUpdate(**data)


def create_login_data(email: str = None, password: str = None) -> Dict[str, str]:
    """Create login data for authentication tests."""
    return {
        "email": email or "test@example.com",
        "password": password or "testpassword123",
    }


# Batch creation helpers

def create_multiple_users(count: int = 5, **kwargs) -> List[User]:
    """Create multiple users with optional overrides."""
    return [UserFactory.build(**kwargs) for _ in range(count)]


def create_multiple_roles(count: int = 3, **kwargs) -> List[Role]:
    """Create multiple roles with optional overrides."""
    return [RoleFactory.build(**kwargs) for _ in range(count)]


def create_multiple_permissions(count: int = 10, **kwargs) -> List[Permission]:
    """Create multiple permissions with optional overrides."""
    return [PermissionFactory.build(**kwargs) for _ in range(count)]


def create_multiple_linked_accounts(count: int = 3, user_id=None, **kwargs) -> List[LinkedAccount]:
    """Create multiple linked accounts with optional user_id."""
    if user_id:
        kwargs["user_id"] = user_id
    return [LinkedAccountFactory.build(**kwargs) for _ in range(count)]


# Predefined permission sets

def create_standard_permissions() -> List[Permission]:
    """Create a standard set of permissions for common API endpoints."""
    permissions = [
        # User permissions
        PermissionFactory.build(name="GET:/api/v1/users", description="Read users list"),
        PermissionFactory.build(name="POST:/api/v1/users", description="Create users"),
        PermissionFactory.build(name="PUT:/api/v1/users/*", description="Update users"),
        PermissionFactory.build(name="DELETE:/api/v1/users/*", description="Delete users"),
        
        # Role permissions
        PermissionFactory.build(name="GET:/api/v1/admin/roles", description="Read roles"),
        PermissionFactory.build(name="POST:/api/v1/admin/roles", description="Create roles"),
        PermissionFactory.build(name="PUT:/api/v1/admin/roles/*", description="Update roles"),
        PermissionFactory.build(name="DELETE:/api/v1/admin/roles/*", description="Delete roles"),
        
        # Permission permissions
        PermissionFactory.build(name="GET:/api/v1/admin/permissions", description="Read permissions"),
        PermissionFactory.build(name="POST:/api/v1/admin/permissions", description="Create permissions"),
        PermissionFactory.build(name="PUT:/api/v1/admin/permissions/*", description="Update permissions"),
        PermissionFactory.build(name="DELETE:/api/v1/admin/permissions/*", description="Delete permissions"),
    ]
    return permissions


def create_standard_roles() -> List[Role]:
    """Create a standard set of roles with descriptions."""
    roles = [
        RoleFactory.build(
            name="admin",
            description="Administrator with full access to all resources"
        ),
        RoleFactory.build(
            name="user_manager",
            description="Can manage users but not system roles and permissions"
        ),
        RoleFactory.build(
            name="viewer",
            description="Read-only access to user information"
        ),
        RoleFactory.build(
            name="editor",
            description="Can edit user profiles and basic information"
        ),
    ]
    return roles


# Complex test scenarios

def create_complete_oauth_scenario():
    """
    Create a complete OAuth test scenario with users, roles, permissions, and assignments.
    Returns a dictionary with all created instances.
    """
    # Create standard permissions and roles
    permissions = create_standard_permissions()
    roles = create_standard_roles()
    
    # Create users with different roles
    admin_user = AdminUserFactory.build()
    manager_user = VerifiedUserFactory.build(email="manager@example.com")
    regular_user = UserFactory.build(email="user@example.com")
    
    users = [admin_user, manager_user, regular_user]
    
    # Create linked accounts for some users
    google_account = GoogleLinkedAccountFactory.build(user_id=regular_user.id)
    linked_accounts = [google_account]
    
    # Create role assignments
    user_roles = [
        UserRoleFactory.build(user_id=admin_user.id, role_id=roles[0].id),  # admin role
        UserRoleFactory.build(user_id=manager_user.id, role_id=roles[1].id),  # user_manager role
        UserRoleFactory.build(user_id=regular_user.id, role_id=roles[2].id),  # viewer role
    ]
    
    # Create permission assignments for roles
    role_permissions = []
    
    # Admin gets all permissions
    for permission in permissions:
        role_permissions.append(
            RolePermissionFactory.build(role_id=roles[0].id, permission_id=permission.id)
        )
    
    # User manager gets user-related permissions
    user_permissions = [p for p in permissions if "users" in p.name]
    for permission in user_permissions:
        role_permissions.append(
            RolePermissionFactory.build(role_id=roles[1].id, permission_id=permission.id)
        )
    
    # Viewer gets only read permissions
    read_permissions = [p for p in permissions if p.name.startswith("GET:")]
    for permission in read_permissions:
        role_permissions.append(
            RolePermissionFactory.build(role_id=roles[2].id, permission_id=permission.id)
        )
    
    return {
        "users": users,
        "admin_user": admin_user,
        "manager_user": manager_user,
        "regular_user": regular_user,
        "roles": roles,
        "permissions": permissions,
        "linked_accounts": linked_accounts,
        "user_roles": user_roles,
        "role_permissions": role_permissions,
    }


def create_sso_test_scenario():
    """Create test scenario focused on SSO functionality."""
    # Create users with various OAuth providers
    google_user = UserFactory.build(email="google.user@gmail.com", password="", is_verified=True)
    facebook_user = UserFactory.build(email="facebook.user@facebook.com", password="", is_verified=True)
    regular_user = UserFactory.build(email="regular@example.com", is_verified=False)
    
    # Create linked accounts
    google_account = LinkedAccountFactory.build(
        user_id=google_user.id,
        provider="google",
        email=google_user.email,
        sub=f"google-{fake.random_number(digits=21)}"
    )
    
    facebook_account = LinkedAccountFactory.build(
        user_id=facebook_user.id,
        provider="facebook", 
        email=facebook_user.email,
        sub=f"facebook-{fake.random_number(digits=15)}"
    )
    
    # User with multiple linked accounts
    multi_provider_user = UserFactory.build(email="multi@example.com", is_verified=True)
    google_link = LinkedAccountFactory.build(
        user_id=multi_provider_user.id,
        provider="google",
        email="multi@gmail.com"
    )
    github_link = LinkedAccountFactory.build(
        user_id=multi_provider_user.id,
        provider="github",
        email="multi@github.com"
    )
    
    return {
        "google_user": google_user,
        "facebook_user": facebook_user,
        "regular_user": regular_user,
        "multi_provider_user": multi_provider_user,
        "linked_accounts": [google_account, facebook_account, google_link, github_link],
        "google_account": google_account,
        "facebook_account": facebook_account,
        "multiple_links": [google_link, github_link],
    }


def create_rbac_test_scenario():
    """Create test scenario focused on RBAC functionality."""
    # Create hierarchical roles
    super_admin = RoleFactory.build(
        name="super_admin",
        description="Super administrator with all permissions"
    )
    
    department_admin = RoleFactory.build(
        name="department_admin", 
        description="Department administrator with limited admin permissions"
    )
    
    team_lead = RoleFactory.build(
        name="team_lead",
        description="Team leader with user management permissions"
    )
    
    employee = RoleFactory.build(
        name="employee",
        description="Regular employee with basic permissions"
    )
    
    roles = [super_admin, department_admin, team_lead, employee]
    
    # Create granular permissions
    permissions = [
        # System permissions
        PermissionFactory.build(name="GET:/api/v1/admin/system", description="View system status"),
        PermissionFactory.build(name="POST:/api/v1/admin/system/backup", description="Create system backup"),
        
        # Department permissions  
        PermissionFactory.build(name="GET:/api/v1/departments", description="View departments"),
        PermissionFactory.build(name="POST:/api/v1/departments", description="Create departments"),
        PermissionFactory.build(name="PUT:/api/v1/departments/*", description="Update departments"),
        
        # Team permissions
        PermissionFactory.build(name="GET:/api/v1/teams", description="View teams"),
        PermissionFactory.build(name="POST:/api/v1/teams", description="Create teams"),
        PermissionFactory.build(name="PUT:/api/v1/teams/*", description="Update teams"),
        
        # User permissions
        PermissionFactory.build(name="GET:/api/v1/users/profile", description="View own profile"),
        PermissionFactory.build(name="PUT:/api/v1/users/profile", description="Update own profile"),
    ]
    
    # Create users with different role assignments
    users = [
        UserFactory.build(email="superadmin@company.com", name="Super Admin"),
        UserFactory.build(email="deptadmin@company.com", name="Department Admin"),
        UserFactory.build(email="teamlead@company.com", name="Team Lead"),
        UserFactory.build(email="employee@company.com", name="Employee"),
    ]
    
    return {
        "roles": roles,
        "permissions": permissions,
        "users": users,
        "super_admin": super_admin,
        "department_admin": department_admin,
        "team_lead": team_lead,
        "employee": employee,
    }


# Utility functions for test data validation

def validate_user_data(user_data: Dict[str, Any]) -> bool:
    """Validate user data has required fields."""
    required_fields = ["email", "name", "password"]
    return all(field in user_data for field in required_fields)


def validate_role_data(role_data: Dict[str, Any]) -> bool:
    """Validate role data has required fields."""
    required_fields = ["name", "description"]
    return all(field in role_data for field in required_fields)


def validate_permission_data(permission_data: Dict[str, Any]) -> bool:
    """Validate permission data has required fields."""
    required_fields = ["name", "description"]
    return all(field in permission_data for field in required_fields) 