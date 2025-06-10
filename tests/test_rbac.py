import pytest
from uuid import uuid4

from app.rbac.models import Role, Permission, UserRole, RolePermission
from app.rbac.services import RoleService, PermissionService, RBACService
from app.rbac.schemas import RoleCreate, PermissionCreate, RoleFilter, PermissionFilter

# Import factories
from tests.factories import (
    RoleFactory, AdminRoleFactory, UserManagerRoleFactory, ViewerRoleFactory,
    PermissionFactory, UserPermissionFactory, AdminPermissionFactory,
    UserRoleFactory, RolePermissionFactory,
    create_role_create_schema, create_role_update_schema,
    create_permission_create_schema, create_permission_update_schema,
    create_standard_roles, create_standard_permissions,
    create_rbac_test_scenario
)


class TestRoleService:
    """Test suite for RoleService."""

    @pytest.mark.asyncio
    async def test_create_role_success(self, role_service: RoleService, sample_role_create: RoleCreate):
        """Test successful role creation."""
        # Act
        role = await role_service.create_role(sample_role_create)
        
        # Assert
        assert role is not None
        assert role.name == sample_role_create.name
        assert role.description == sample_role_create.description
        assert role.id is not None
        assert role.created_at is not None
        assert role.updated_at is not None

    @pytest.mark.asyncio
    async def test_create_role_minimal_data(self, role_service: RoleService):
        """Test role creation with minimal data."""
        # Arrange - Use factory
        role_create = create_role_create_schema(name="minimal_role", description="")
        
        # Act
        role = await role_service.create_role(role_create)
        
        # Assert
        assert role.name == "minimal_role"
        assert role.description == ""

    @pytest.mark.asyncio
    async def test_get_role_success(self, role_service: RoleService, created_role: Role):
        """Test successful role retrieval by ID."""
        # Act
        retrieved_role = await role_service.get_role(str(created_role.id))
        
        # Assert
        assert retrieved_role is not None
        assert retrieved_role.id == created_role.id
        assert retrieved_role.name == created_role.name
        assert retrieved_role.description == created_role.description

    @pytest.mark.asyncio
    async def test_get_role_not_found(self, role_service: RoleService):
        """Test role retrieval with non-existent ID."""
        # Arrange
        non_existent_id = str(uuid4())
        
        # Act
        role = await role_service.get_role(non_existent_id)
        
        # Assert
        assert role is None

    @pytest.mark.asyncio
    async def test_update_role_success(self, role_service: RoleService, created_role: Role):
        """Test successful role update."""
        # Arrange - Use factory to create update schema
        role_update = create_role_update_schema(
            id=str(created_role.id),
            name="updated_role_name",
            description="Updated role description"
        )
        
        # Act
        updated_role = await role_service.update_role(role_update)
        
        # Assert
        assert updated_role.id == created_role.id
        assert updated_role.name == "updated_role_name"
        assert updated_role.description == "Updated role description"

    @pytest.mark.asyncio
    async def test_update_role_not_found(self, role_service: RoleService):
        """Test updating non-existent role raises ValueError."""
        # Arrange - Use factory
        role_update = create_role_update_schema(
            id=str(uuid4()),
            name="nonexistent", 
            description="test"
        )
        
        # Act & Assert
        with pytest.raises(ValueError, match="Role not found"):
            await role_service.update_role(role_update)

    @pytest.mark.asyncio
    async def test_get_roles_empty(self, role_service: RoleService):
        """Test getting roles when database is empty."""
        # Arrange
        filter_obj = RoleFilter(name="", description="")
        
        # Act
        roles = await role_service.get_roles(filter_obj)
        
        # Assert
        assert roles == []

    @pytest.mark.asyncio
    async def test_get_roles_with_data(self, role_service: RoleService):
        """Test getting roles with data in database."""
        # Arrange - Use factory
        role1_create = create_role_create_schema(name="role1", description="First role")
        role2_create = create_role_create_schema(name="role2", description="Second role")
        
        role1 = await role_service.create_role(role1_create)
        role2 = await role_service.create_role(role2_create)
        
        filter_obj = RoleFilter(name="", description="")
        
        # Act
        roles = await role_service.get_roles(filter_obj)
        
        # Assert
        assert len(roles) == 2
        role_names = [role.name for role in roles]
        assert "role1" in role_names
        assert "role2" in role_names

    @pytest.mark.asyncio
    async def test_get_roles_with_name_filter(self, role_service: RoleService):
        """Test getting roles with name filter."""
        # Arrange - Use factory
        admin_create = create_role_create_schema(name="admin", description="Admin role")
        user_create = create_role_create_schema(name="user", description="User role")
        
        role1 = await role_service.create_role(admin_create)
        role2 = await role_service.create_role(user_create)
        
        filter_obj = RoleFilter(name="admin", description="")
        
        # Act
        roles = await role_service.get_roles(filter_obj)
        
        # Assert
        assert len(roles) == 1
        assert roles[0].name == "admin"

    @pytest.mark.asyncio
    async def test_get_roles_with_description_filter(self, role_service: RoleService):
        """Test getting roles with description filter."""
        # Arrange - Use factory
        special_create = create_role_create_schema(name="role1", description="Special role")
        normal_create = create_role_create_schema(name="role2", description="Normal role")
        
        role1 = await role_service.create_role(special_create)
        role2 = await role_service.create_role(normal_create)
        
        filter_obj = RoleFilter(name="", description="Special role")
        
        # Act
        roles = await role_service.get_roles(filter_obj)
        
        # Assert
        assert len(roles) == 1
        assert roles[0].description == "Special role"

    @pytest.mark.asyncio
    async def test_create_role_with_factory_variations(self, role_service: RoleService):
        """Test creating roles with different factory variations."""
        # Create admin role
        admin_role_create = create_role_create_schema(name="admin", description="Administrator role")
        admin_role = await role_service.create_role(admin_role_create)
        
        # Create manager role
        manager_role_create = create_role_create_schema(name="user_manager", description="User manager role")
        manager_role = await role_service.create_role(manager_role_create)
        
        # Create viewer role
        viewer_role_create = create_role_create_schema(name="viewer", description="Viewer role")
        viewer_role = await role_service.create_role(viewer_role_create)
        
        # Assert
        assert admin_role.name == "admin"
        assert manager_role.name == "user_manager"
        assert viewer_role.name == "viewer"
        assert admin_role.id != manager_role.id != viewer_role.id


class TestPermissionService:
    """Test suite for PermissionService."""

    @pytest.mark.asyncio
    async def test_create_permission_success(self, permission_service: PermissionService, sample_permission_create: PermissionCreate):
        """Test successful permission creation."""
        # Act
        permission = await permission_service.create_permission(sample_permission_create)
        
        # Assert
        assert permission is not None
        assert permission.name == sample_permission_create.name
        assert permission.description == sample_permission_create.description
        assert permission.id is not None
        assert permission.created_at is not None
        assert permission.updated_at is not None

    @pytest.mark.asyncio
    async def test_create_permission_minimal_data(self, permission_service: PermissionService):
        """Test permission creation with minimal data."""
        # Arrange - Use factory
        permission_create = create_permission_create_schema(
            name="POST:/api/v1/minimal",
            description=""
        )
        
        # Act
        permission = await permission_service.create_permission(permission_create)
        
        # Assert
        assert permission.name == "POST:/api/v1/minimal"
        assert permission.description == ""

    @pytest.mark.asyncio
    async def test_get_permission_success(self, permission_service: PermissionService, created_permission: Permission):
        """Test successful permission retrieval by ID."""
        # Act
        retrieved_permission = await permission_service.get_permission(str(created_permission.id))
        
        # Assert
        assert retrieved_permission is not None
        assert retrieved_permission.id == created_permission.id
        assert retrieved_permission.name == created_permission.name
        assert retrieved_permission.description == created_permission.description

    @pytest.mark.asyncio
    async def test_get_permission_not_found(self, permission_service: PermissionService):
        """Test permission retrieval with non-existent ID."""
        # Arrange
        non_existent_id = str(uuid4())
        
        # Act
        permission = await permission_service.get_permission(non_existent_id)
        
        # Assert
        assert permission is None

    @pytest.mark.asyncio
    async def test_update_permission_success(self, permission_service: PermissionService, created_permission: Permission):
        """Test successful permission update."""
        # Arrange - Use factory
        permission_update = create_permission_update_schema(
            id=str(created_permission.id),
            name="PUT:/api/v1/updated",
            description="Updated permission description"
        )
        
        # Act
        updated_permission = await permission_service.update_permission(permission_update)
        
        # Assert
        assert updated_permission.id == created_permission.id
        assert updated_permission.name == "PUT:/api/v1/updated"
        assert updated_permission.description == "Updated permission description"

    @pytest.mark.asyncio
    async def test_update_permission_not_found(self, permission_service: PermissionService):
        """Test updating non-existent permission raises ValueError."""
        # Arrange - Use factory
        permission_update = create_permission_update_schema(
            id=str(uuid4()),
            name="DELETE:/api/v1/nonexistent",
            description="test"
        )
        
        # Act & Assert
        with pytest.raises(ValueError, match="Permission not found"):
            await permission_service.update_permission(permission_update)

    @pytest.mark.asyncio
    async def test_get_permissions_empty(self, permission_service: PermissionService):
        """Test getting permissions when database is empty."""
        # Arrange
        filter_obj = PermissionFilter(name="", description="")
        
        # Act
        permissions = await permission_service.get_permissions(filter_obj)
        
        # Assert
        assert permissions == []

    @pytest.mark.asyncio
    async def test_get_permissions_with_data(self, permission_service: PermissionService):
        """Test getting permissions with data in database."""
        # Arrange - Use factory
        perm1_create = create_permission_create_schema(
            name="GET:/api/v1/users",
            description="Read users"
        )
        perm2_create = create_permission_create_schema(
            name="POST:/api/v1/users",
            description="Create users"
        )
        
        perm1 = await permission_service.create_permission(perm1_create)
        perm2 = await permission_service.create_permission(perm2_create)
        
        filter_obj = PermissionFilter(name="", description="")
        
        # Act
        permissions = await permission_service.get_permissions(filter_obj)
        
        # Assert
        assert len(permissions) == 2
        permission_names = [perm.name for perm in permissions]
        assert "GET:/api/v1/users" in permission_names
        assert "POST:/api/v1/users" in permission_names

    @pytest.mark.asyncio
    async def test_get_permissions_with_name_filter(self, permission_service: PermissionService):
        """Test getting permissions with name filter."""
        # Arrange - Use factory
        get_perm_create = create_permission_create_schema(
            name="GET:/api/v1/users",
            description="Read users"
        )
        post_perm_create = create_permission_create_schema(
            name="POST:/api/v1/users",
            description="Create users"
        )
        
        perm1 = await permission_service.create_permission(get_perm_create)
        perm2 = await permission_service.create_permission(post_perm_create)
        
        filter_obj = PermissionFilter(name="GET:/api/v1/users", description="")
        
        # Act
        permissions = await permission_service.get_permissions(filter_obj)
        
        # Assert
        assert len(permissions) == 1
        assert permissions[0].name == "GET:/api/v1/users"

    @pytest.mark.asyncio
    async def test_create_permission_with_factory_variations(self, permission_service: PermissionService):
        """Test creating permissions with different factory variations."""
        # Create user permission
        user_perm_create = create_permission_create_schema(
            name="GET:/api/v1/users",
            description="User management permission"
        )
        user_perm = await permission_service.create_permission(user_perm_create)
        
        # Create admin permission
        admin_perm_create = create_permission_create_schema(
            name="POST:/api/v1/admin/roles", 
            description="Administrative permission"
        )
        admin_perm = await permission_service.create_permission(admin_perm_create)
        
        # Assert
        assert "users" in user_perm.name
        assert "admin" in admin_perm.name
        assert user_perm.id != admin_perm.id


class TestRBACService:
    """Test suite for RBACService."""

    @pytest.mark.asyncio
    async def test_assign_role_to_user_success(self, rbac_service: RBACService):
        """Test successful role assignment to user."""
        # Arrange
        user_id = str(uuid4())
        role_id = str(uuid4())
        
        # Act
        user_role = await rbac_service.assign_role_to_user(user_id, role_id)
        
        # Assert
        assert user_role is not None
        assert str(user_role.user_id) == user_id
        assert str(user_role.role_id) == role_id
        assert user_role.id is not None
        assert user_role.created_at is not None
        assert user_role.updated_at is not None

    @pytest.mark.asyncio
    async def test_assign_permission_to_role_success(self, rbac_service: RBACService):
        """Test successful permission assignment to role."""
        # Arrange
        role_id = str(uuid4())
        permission_id = str(uuid4())
        
        # Act
        role_permission = await rbac_service.assign_permission_to_role(role_id, permission_id)
        
        # Assert
        assert role_permission is not None
        assert str(role_permission.role_id) == role_id
        assert str(role_permission.permission_id) == permission_id
        assert role_permission.id is not None
        assert role_permission.created_at is not None
        assert role_permission.updated_at is not None

    @pytest.mark.asyncio
    async def test_multiple_role_assignments(self, rbac_service: RBACService):
        """Test assigning multiple roles to the same user."""
        # Arrange
        user_id = str(uuid4())
        role_id_1 = str(uuid4())
        role_id_2 = str(uuid4())
        
        # Act
        user_role_1 = await rbac_service.assign_role_to_user(user_id, role_id_1)
        user_role_2 = await rbac_service.assign_role_to_user(user_id, role_id_2)
        
        # Assert
        assert user_role_1.user_id == user_role_2.user_id
        assert user_role_1.role_id != user_role_2.role_id
        assert user_role_1.id != user_role_2.id

    @pytest.mark.asyncio
    async def test_multiple_permission_assignments(self, rbac_service: RBACService):
        """Test assigning multiple permissions to the same role."""
        # Arrange
        role_id = str(uuid4())
        permission_id_1 = str(uuid4())
        permission_id_2 = str(uuid4())
        
        # Act
        role_perm_1 = await rbac_service.assign_permission_to_role(role_id, permission_id_1)
        role_perm_2 = await rbac_service.assign_permission_to_role(role_id, permission_id_2)
        
        # Assert
        assert role_perm_1.role_id == role_perm_2.role_id
        assert role_perm_1.permission_id != role_perm_2.permission_id
        assert role_perm_1.id != role_perm_2.id

    @pytest.mark.asyncio
    async def test_rbac_assignments_with_factories(self, rbac_service: RBACService):
        """Test RBAC assignments using factory-generated IDs."""
        # Arrange - Use factories to generate realistic data structures
        user_data = UserRoleFactory.build()
        role_perm_data = RolePermissionFactory.build()
        
        # Act
        user_role = await rbac_service.assign_role_to_user(
            str(user_data.user_id), 
            str(user_data.role_id)
        )
        role_permission = await rbac_service.assign_permission_to_role(
            str(role_perm_data.role_id),
            str(role_perm_data.permission_id)
        )
        
        # Assert
        assert user_role.user_id == user_data.user_id
        assert user_role.role_id == user_data.role_id
        assert role_permission.role_id == role_perm_data.role_id  
        assert role_permission.permission_id == role_perm_data.permission_id


class TestRoleModel:
    """Test suite for Role model."""

    def test_role_model_creation(self):
        """Test Role model creation with all fields."""
        # Arrange & Act - Use factory for realistic data
        role_data = RoleFactory.build()
        role = Role(
            name=role_data.name,
            description=role_data.description
        )
        
        # Assert
        assert role.name == role_data.name
        assert role.description == role_data.description

    def test_role_model_defaults(self):
        """Test Role model default values."""
        # Arrange & Act
        role = Role(name="test_role")
        
        # Assert
        assert role.name == "test_role"
        assert role.description == ""

    def test_role_factory_direct(self):
        """Test Role factory direct usage."""
        # Arrange & Act
        role = RoleFactory.build()
        
        # Assert
        assert role.name is not None
        assert role.description is not None

    def test_specialized_role_factories(self):
        """Test specialized role factories."""
        # Test admin role factory
        admin_role = AdminRoleFactory.build()
        assert admin_role.name == "admin"
        assert "Administrator" in admin_role.description
        
        # Test user manager role factory
        manager_role = UserManagerRoleFactory.build()
        assert manager_role.name == "user_manager"
        assert "manage users" in manager_role.description
        
        # Test viewer role factory
        viewer_role = ViewerRoleFactory.build()
        assert viewer_role.name == "viewer"
        assert "Read-only" in viewer_role.description


class TestPermissionModel:
    """Test suite for Permission model."""

    def test_permission_model_creation(self):
        """Test Permission model creation with all fields."""
        # Arrange & Act - Use factory for realistic data
        permission_data = PermissionFactory.build()
        permission = Permission(
            name=permission_data.name,
            description=permission_data.description
        )
        
        # Assert
        assert permission.name == permission_data.name
        assert permission.description == permission_data.description

    def test_permission_model_defaults(self):
        """Test Permission model default values."""
        # Arrange & Act
        permission = Permission(name="POST:/api/v1/test")
        
        # Assert
        assert permission.name == "POST:/api/v1/test"
        assert permission.description == ""

    def test_permission_name_format(self):
        """Test permission name follows expected format."""
        # Arrange & Act - Use factory
        permission = PermissionFactory.build()
        
        # Assert
        assert ":" in permission.name  # Should have HTTP method and path format
        assert "/api/v1/" in permission.name or permission.name.startswith(("GET:", "POST:", "PUT:", "DELETE:"))

    def test_permission_factory_direct(self):
        """Test Permission factory direct usage."""
        # Arrange & Act
        permission = PermissionFactory.build()
        
        # Assert
        assert permission.name is not None
        assert ":" in permission.name
        assert permission.description is not None

    def test_specialized_permission_factories(self):
        """Test specialized permission factories."""
        # Test user permission factory
        user_perm = UserPermissionFactory.build()
        assert "/api/v1/users" in user_perm.name
        assert "User management" in user_perm.description
        
        # Test admin permission factory
        admin_perm = AdminPermissionFactory.build()
        assert "/api/v1/admin/" in admin_perm.name
        assert "Administrative" in admin_perm.description


class TestUserRoleModel:
    """Test suite for UserRole model."""

    def test_user_role_model_creation(self):
        """Test UserRole model creation."""
        # Arrange
        user_id = uuid4()
        role_id = uuid4()
        
        # Act
        user_role = UserRole(user_id=user_id, role_id=role_id)
        
        # Assert
        assert user_role.user_id == user_id
        assert user_role.role_id == role_id

    def test_user_role_factory_direct(self):
        """Test UserRole factory direct usage."""
        # Arrange & Act
        user_role = UserRoleFactory.build()
        
        # Assert
        assert user_role.user_id is not None
        assert user_role.role_id is not None
        assert user_role.id is not None


class TestRolePermissionModel:
    """Test suite for RolePermission model."""

    def test_role_permission_model_creation(self):
        """Test RolePermission model creation."""
        # Arrange
        role_id = uuid4()
        permission_id = uuid4()
        
        # Act
        role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
        
        # Assert
        assert role_permission.role_id == role_id
        assert role_permission.permission_id == permission_id

    def test_role_permission_factory_direct(self):
        """Test RolePermission factory direct usage."""
        # Arrange & Act
        role_permission = RolePermissionFactory.build()
        
        # Assert
        assert role_permission.role_id is not None
        assert role_permission.permission_id is not None
        assert role_permission.id is not None


class TestIntegrationRBAC:
    """Integration tests for RBAC functionality."""

    @pytest.mark.asyncio
    async def test_complete_rbac_workflow(
        self, 
        role_service: RoleService, 
        permission_service: PermissionService, 
        rbac_service: RBACService
    ):
        """Test complete RBAC workflow: create role and permission, then assign them."""
        # Arrange & Act - Use factories
        # Create role
        role_create = create_role_create_schema(
            name="editor",
            description="Content editor role"
        )
        role = await role_service.create_role(role_create)
        
        # Create permission
        permission_create = create_permission_create_schema(
            name="PUT:/api/v1/content",
            description="Edit content"
        )
        permission = await permission_service.create_permission(permission_create)
        
        # Assign permission to role
        role_permission = await rbac_service.assign_permission_to_role(
            str(role.id), str(permission.id)
        )
        
        # Assign role to user
        user_id = str(uuid4())
        user_role = await rbac_service.assign_role_to_user(user_id, str(role.id))
        
        # Assert
        assert role.name == "editor"
        assert permission.name == "PUT:/api/v1/content"
        assert str(role_permission.role_id) == str(role.id)
        assert str(role_permission.permission_id) == str(permission.id)
        assert str(user_role.user_id) == user_id
        assert str(user_role.role_id) == str(role.id)

    @pytest.mark.asyncio
    async def test_rbac_workflow_with_standard_data(
        self,
        role_service: RoleService,
        permission_service: PermissionService, 
        rbac_service: RBACService
    ):
        """Test RBAC workflow using standard factory data sets."""
        # Arrange - Use factory standard data
        standard_roles_data = create_standard_roles()
        standard_permissions_data = create_standard_permissions()
        
        # Create roles in database
        created_roles = []
        for role_data in standard_roles_data[:2]:  # Create first 2 roles
            role_create = create_role_create_schema(
                name=role_data.name,
                description=role_data.description
            )
            role = await role_service.create_role(role_create)
            created_roles.append(role)
            
        # Create permissions in database
        created_permissions = []
        for perm_data in standard_permissions_data[:3]:  # Create first 3 permissions
            perm_create = create_permission_create_schema(
                name=perm_data.name,
                description=perm_data.description
            )
            permission = await permission_service.create_permission(perm_create)
            created_permissions.append(permission)
        
        # Act - Assign permissions to roles
        role_permissions = []
        for role in created_roles:
            for permission in created_permissions:
                role_perm = await rbac_service.assign_permission_to_role(
                    str(role.id), str(permission.id)
                )
                role_permissions.append(role_perm)
        
        # Assert
        assert len(created_roles) == 2
        assert len(created_permissions) == 3
        assert len(role_permissions) == 6  # 2 roles * 3 permissions
        
        # Verify standard role names
        role_names = [role.name for role in created_roles]
        assert "admin" in role_names
        assert "user_manager" in role_names


class TestFactoryIntegration:
    """Test factory integration with RBAC services."""

    @pytest.mark.asyncio
    async def test_rbac_scenario_creation(self, role_service: RoleService, permission_service: PermissionService):
        """Test creating complex RBAC scenarios with factories."""
        # Arrange - Use factory scenario
        scenario = create_rbac_test_scenario()
        
        # Act - Create roles and permissions in database using scenario data
        created_roles = []
        for role_data in scenario["roles"]:
            role_create = create_role_create_schema(
                name=role_data.name,
                description=role_data.description
            )
            role = await role_service.create_role(role_create)
            created_roles.append(role)
            
        created_permissions = []
        for perm_data in scenario["permissions"]:
            perm_create = create_permission_create_schema(
                name=perm_data.name, 
                description=perm_data.description
            )
            permission = await permission_service.create_permission(perm_create)
            created_permissions.append(permission)
        
        # Assert
        assert len(created_roles) == 4  # super_admin, department_admin, team_lead, employee
        assert len(created_permissions) > 5  # Should have system, department, team, user permissions
        
        # Verify hierarchical role names
        role_names = [role.name for role in created_roles]
        assert "super_admin" in role_names
        assert "department_admin" in role_names
        assert "team_lead" in role_names
        assert "employee" in role_names
