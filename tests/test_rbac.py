import pytest
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession

from app.rbac.models import Role, Permission, UserRole, RolePermission
from app.rbac.services import RoleService, PermissionService, RBACService
from app.rbac.schemas import RoleCreate, PermissionCreate, RoleUpdate, PermissionUpdate, RoleFilter, PermissionFilter


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
        # Arrange
        role_create = RoleCreate(name="minimal_role", description="")
        
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
        # Arrange
        role_update = RoleUpdate(
            name="updated_role_name",
            description="Updated role description"
        )
        # Manually set the id since RoleUpdate doesn't have it as a field
        setattr(role_update, 'id', str(created_role.id))
        
        # Act
        updated_role = await role_service.update_role(role_update)
        
        # Assert
        assert updated_role.id == created_role.id
        assert updated_role.name == "updated_role_name"
        assert updated_role.description == "Updated role description"

    @pytest.mark.asyncio
    async def test_update_role_not_found(self, role_service: RoleService):
        """Test updating non-existent role raises ValueError."""
        # Arrange
        role_update = RoleUpdate(name="nonexistent", description="test")
        # Manually set the id since RoleUpdate doesn't have it as a field
        setattr(role_update, 'id', str(uuid4()))
        
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
        # Arrange
        role1 = await role_service.create_role(RoleCreate(name="role1", description="First role"))
        role2 = await role_service.create_role(RoleCreate(name="role2", description="Second role"))
        
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
        # Arrange
        role1 = await role_service.create_role(RoleCreate(name="admin", description="Admin role"))
        role2 = await role_service.create_role(RoleCreate(name="user", description="User role"))
        
        filter_obj = RoleFilter(name="admin", description="")
        
        # Act
        roles = await role_service.get_roles(filter_obj)
        
        # Assert
        assert len(roles) == 1
        assert roles[0].name == "admin"

    @pytest.mark.asyncio
    async def test_get_roles_with_description_filter(self, role_service: RoleService):
        """Test getting roles with description filter."""
        # Arrange
        role1 = await role_service.create_role(RoleCreate(name="role1", description="Special role"))
        role2 = await role_service.create_role(RoleCreate(name="role2", description="Normal role"))
        
        filter_obj = RoleFilter(name="", description="Special role")
        
        # Act
        roles = await role_service.get_roles(filter_obj)
        
        # Assert
        assert len(roles) == 1
        assert roles[0].description == "Special role"


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
        # Arrange
        permission_create = PermissionCreate(name="POST:/api/v1/minimal", description="")
        
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
        # Arrange
        permission_update = PermissionUpdate(
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
        # Arrange
        permission_update = PermissionUpdate(name="DELETE:/api/v1/nonexistent", description="test")
        # Manually set the id since PermissionUpdate doesn't have it as a field
        setattr(permission_update, 'id', str(uuid4()))
        
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
        # Arrange
        perm1 = await permission_service.create_permission(
            PermissionCreate(name="GET:/api/v1/users", description="Read users")
        )
        perm2 = await permission_service.create_permission(
            PermissionCreate(name="POST:/api/v1/users", description="Create users")
        )
        
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
        # Arrange
        perm1 = await permission_service.create_permission(
            PermissionCreate(name="GET:/api/v1/users", description="Read users")
        )
        perm2 = await permission_service.create_permission(
            PermissionCreate(name="POST:/api/v1/users", description="Create users")
        )
        
        filter_obj = PermissionFilter(name="GET:/api/v1/users", description="")
        
        # Act
        permissions = await permission_service.get_permissions(filter_obj)
        
        # Assert
        assert len(permissions) == 1
        assert permissions[0].name == "GET:/api/v1/users"


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


class TestRoleModel:
    """Test suite for Role model."""

    def test_role_model_creation(self):
        """Test Role model creation with all fields."""
        # Arrange & Act
        role = Role(
            name="admin",
            description="Administrator role with full access"
        )
        
        # Assert
        assert role.name == "admin"
        assert role.description == "Administrator role with full access"

    def test_role_model_defaults(self):
        """Test Role model default values."""
        # Arrange & Act
        role = Role(name="test_role")
        
        # Assert
        assert role.name == "test_role"
        assert role.description == ""


class TestPermissionModel:
    """Test suite for Permission model."""

    def test_permission_model_creation(self):
        """Test Permission model creation with all fields."""
        # Arrange & Act
        permission = Permission(
            name="GET:/api/v1/users",
            description="Permission to read user list"
        )
        
        # Assert
        assert permission.name == "GET:/api/v1/users"
        assert permission.description == "Permission to read user list"

    def test_permission_model_defaults(self):
        """Test Permission model default values."""
        # Arrange & Act
        permission = Permission(name="POST:/api/v1/test")
        
        # Assert
        assert permission.name == "POST:/api/v1/test"
        assert permission.description == ""

    def test_permission_name_format(self):
        """Test permission name follows expected format."""
        # Arrange & Act
        permission = Permission(name="DELETE:/api/v1/users/123")
        
        # Assert
        assert permission.name.startswith("DELETE:")
        assert "/api/v1/" in permission.name


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
        # Arrange & Act
        # Create role
        role = await role_service.create_role(
            RoleCreate(name="editor", description="Content editor role")
        )
        
        # Create permission
        permission = await permission_service.create_permission(
            PermissionCreate(name="PUT:/api/v1/content", description="Edit content")
        )
        
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
