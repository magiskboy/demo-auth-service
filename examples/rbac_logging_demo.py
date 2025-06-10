#!/usr/bin/env python3
"""
RBAC Logging demonstration script for the OAuth2 service.

This script demonstrates logging features in the RBAC system:
- Role creation, update, and deletion logging
- Permission management logging  
- Role assignment and revocation logging
- Security event logging for RBAC operations
- Error handling and comprehensive logging
"""

import asyncio
import os
import sys
from uuid import uuid4

# Add the parent directory to the path so we can import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.logging import setup_logging, get_logger
from app.rbac.services import RoleService, PermissionService, RBACService
from app.rbac.schemas import RoleCreate, PermissionCreate, RoleUpdate, PermissionUpdate, RoleFilter, PermissionFilter

# Mock database session for demonstration
class MockSession:
    """Mock database session for demonstration purposes."""
    
    def __init__(self):
        self.objects = {}
        self.next_id = 1
        
    def add(self, obj):
        if not hasattr(obj, 'id') or obj.id is None:
            obj.id = str(self.next_id)
            self.next_id += 1
        # Store by string key to handle UUIDs properly
        key = str(obj.id)
        self.objects[key] = obj
        
    async def commit(self):
        pass
        
    async def refresh(self, obj):
        pass
        
    async def get(self, model, obj_id):
        # Convert obj_id to string for lookup
        key = str(obj_id)
        return self.objects.get(key)
        
    async def execute(self, query):
        # Mock query execution - return empty result for now
        # In a real implementation, this would parse the query
        return MockResult([])
        
    async def delete(self, obj):
        key = str(obj.id)
        if key in self.objects:
            del self.objects[key]

class MockResult:
    """Mock query result."""
    def __init__(self, items):
        self.items = items
        
    def scalars(self):
        return MockScalars(self.items)
        
    def scalar_one_or_none(self):
        return self.items[0] if self.items else None

class MockScalars:
    """Mock scalars result."""
    def __init__(self, items):
        self.items = items
        
    def all(self):
        return self.items


async def demo_role_operations():
    """Demonstrate role operations with logging."""
    print("\n=== Demo: Role Operations Logging ===")
    
    db = MockSession()
    role_service = RoleService(db)
    admin_user_id = str(uuid4())
    
    # Create roles
    print("\n--- Creating Roles ---")
    admin_role = await role_service.create_role(
        RoleCreate(name="admin", description="Administrator role"),
        user_id=admin_user_id
    )
    
    user_role = await role_service.create_role(
        RoleCreate(name="user", description="Regular user role"),
        user_id=admin_user_id
    )
    
    # Get role
    print("\n--- Retrieving Roles ---")
    retrieved_role = await role_service.get_role(str(admin_role.id), admin_user_id)
    if retrieved_role:
        print(f"Retrieved role: {retrieved_role.name}")
    else:
        print("Role not found during retrieval")
    
    # Update role
    print("\n--- Updating Role ---")
    updated_role = await role_service.update_role(
        RoleUpdate(id=str(admin_role.id), name="super_admin", description="Super administrator role"),
        user_id=admin_user_id
    )
    
    # Get all roles
    print("\n--- Listing All Roles ---")
    all_roles = await role_service.get_roles(RoleFilter(), admin_user_id)
    
    # Delete role
    print("\n--- Deleting Role ---")
    deleted = await role_service.delete_role(str(user_role.id), admin_user_id)
    
    print(f"Role operations completed. Created: {admin_role.name}, Updated: {updated_role.name}, Deleted: {deleted}")


async def demo_permission_operations():
    """Demonstrate permission operations with logging."""
    print("\n=== Demo: Permission Operations Logging ===")
    
    db = MockSession()
    permission_service = PermissionService(db)
    admin_user_id = str(uuid4())
    
    # Create permissions
    print("\n--- Creating Permissions ---")
    read_users_perm = await permission_service.create_permission(
        PermissionCreate(name="GET:/api/v1/users", description="Read users"),
        user_id=admin_user_id
    )
    
    create_users_perm = await permission_service.create_permission(
        PermissionCreate(name="POST:/api/v1/users", description="Create users"),
        user_id=admin_user_id
    )
    
    # Get permission
    print("\n--- Retrieving Permission ---")
    retrieved_perm = await permission_service.get_permission(str(read_users_perm.id), admin_user_id)
    if retrieved_perm:
        print(f"Retrieved permission: {retrieved_perm.name}")
    else:
        print("Permission not found during retrieval")
    
    # Update permission
    print("\n--- Updating Permission ---")
    updated_perm = await permission_service.update_permission(
        PermissionUpdate(
            id=str(read_users_perm.id), 
            name="GET:/api/v1/users/*", 
            description="Read all user data"
        ),
        user_id=admin_user_id
    )
    
    # Get all permissions
    print("\n--- Listing All Permissions ---")
    all_permissions = await permission_service.get_permissions(PermissionFilter(), admin_user_id)
    
    # Delete permission
    print("\n--- Deleting Permission ---")
    deleted = await permission_service.delete_permission(str(create_users_perm.id), admin_user_id)
    
    print(f"Permission operations completed. Created: {read_users_perm.name}, Updated: {updated_perm.name}, Deleted: {deleted}")


async def demo_rbac_assignments():
    """Demonstrate RBAC assignment operations with comprehensive security logging."""
    print("\n=== Demo: RBAC Assignment Logging ===")
    
    db = MockSession()
    rbac_service = RBACService(db)
    
    # Mock IDs for the demo
    admin_user_id = str(uuid4())  # The user performing the operations
    target_user_id = str(uuid4())  # The user receiving role assignments
    role_id = str(uuid4())
    permission_id = str(uuid4())
    
    print("\n--- Assigning Role to User ---")
    user_role_assignment = await rbac_service.assign_role_to_user(
        user_id=target_user_id,
        role_id=role_id,
        assigned_by=admin_user_id
    )
    
    print("\n--- Assigning Permission to Role ---")
    role_permission_assignment = await rbac_service.assign_permission_to_role(
        role_id=role_id,
        permission_id=permission_id,
        assigned_by=admin_user_id
    )
    
    print("\n--- Getting User Roles ---")
    user_roles = await rbac_service.get_user_roles(target_user_id, admin_user_id)
    
    print("\n--- Getting Role Permissions ---")
    role_permissions = await rbac_service.get_role_permissions(role_id, admin_user_id)
    
    print("\n--- Revoking Permission from Role ---")
    permission_revoked = await rbac_service.revoke_permission_from_role(
        role_id=role_id,
        permission_id=permission_id,
        revoked_by=admin_user_id
    )
    
    print("\n--- Revoking Role from User ---")
    role_revoked = await rbac_service.revoke_role_from_user(
        user_id=target_user_id,
        role_id=role_id,
        revoked_by=admin_user_id
    )
    
    print(f"RBAC operations completed. Assignments created and revoked: Role={role_revoked}, Permission={permission_revoked}")


async def demo_error_handling():
    """Demonstrate error handling and logging in RBAC operations."""
    print("\n=== Demo: Error Handling Logging ===")
    
    db = MockSession()
    role_service = RoleService(db)
    admin_user_id = str(uuid4())
    
    print("\n--- Attempting Invalid Operations ---")
    
    # Try to get non-existent role
    try:
        non_existent_role = await role_service.get_role("non-existent-id", admin_user_id)
        print(f"Non-existent role result: {non_existent_role}")
    except Exception as e:
        print(f"Expected error handled: {e}")
    
    # Try to update non-existent role
    try:
        await role_service.update_role(
            RoleUpdate(id="non-existent-id", name="test", description="test"),
            user_id=admin_user_id
        )
    except ValueError as e:
        print(f"Expected ValueError caught and logged: {e}")
    
    # Try to delete non-existent role
    try:
        deleted = await role_service.delete_role("non-existent-id", admin_user_id)
        print(f"Delete non-existent role result: {deleted}")
    except Exception as e:
        print(f"Error handled: {e}")


async def demo_security_events():
    """Demonstrate specific security events that would be logged."""
    print("\n=== Demo: Security Events in RBAC ===")
    
    logger = get_logger('demo.rbac.security')
    
    # Simulate various security-relevant RBAC scenarios
    scenarios = [
        {
            'event': 'privileged_role_created',
            'description': 'Creating a privileged role like super_admin',
            'details': 'Role "super_admin" created with elevated privileges'
        },
        {
            'event': 'bulk_permission_assignment',
            'description': 'Assigning multiple permissions at once',
            'details': 'Bulk assignment of 15 permissions to admin role'
        },
        {
            'event': 'cross_tenant_role_assignment',
            'description': 'Suspicious cross-tenant role assignment',
            'details': 'User from tenant A assigned role from tenant B'
        },
        {
            'event': 'permission_escalation_attempt',
            'description': 'Attempt to assign higher privileges',
            'details': 'User attempted to assign admin role without sufficient privileges'
        }
    ]
    
    for scenario in scenarios:
        logger.warning(
            f"Security event: {scenario['description']}",
            extra={
                'event_type': 'rbac_security_event',
                'security_event_type': scenario['event'],
                'details': scenario['details'],
                'timestamp': asyncio.get_event_loop().time()
            }
        )
    
    print("Security event scenarios logged")


async def demo_audit_trail():
    """Demonstrate audit trail logging for RBAC operations."""
    print("\n=== Demo: RBAC Audit Trail ===")
    
    logger = get_logger('demo.rbac.audit')
    
    # Simulate a complete RBAC workflow with audit logging
    workflow_steps = [
        "Admin user 'admin@company.com' logged in",
        "Created new role 'project_manager' with ID: pm-123",
        "Created permission 'MANAGE:/api/v1/projects' with ID: perm-456",
        "Assigned permission perm-456 to role pm-123",
        "Assigned role pm-123 to user 'manager@company.com'",
        "User 'manager@company.com' attempted to access /api/v1/projects",
        "Access granted based on role pm-123 permissions",
        "Modified role pm-123 description to include project deletion rights",
        "Revoked role pm-123 from user 'manager@company.com' (user left company)",
        "Deleted role pm-123 and associated permissions"
    ]
    
    for i, step in enumerate(workflow_steps, 1):
        logger.info(
            f"Audit Step {i}: {step}",
            extra={
                'event_type': 'rbac_audit',
                'workflow_step': i,
                'total_steps': len(workflow_steps),
                'audit_details': step
            }
        )
    
    print("RBAC audit trail workflow logged")


async def main():
    """Run all RBAC logging demonstrations."""
    print("OAuth2 Service RBAC Logging Demonstration")
    print("=" * 60)
    
    # Setup logging
    setup_logging()
    
    # Run demonstrations
    await demo_role_operations()
    await demo_permission_operations()
    await demo_rbac_assignments()
    await demo_error_handling()
    await demo_security_events()
    await demo_audit_trail()
    
    print(f"\n=== Summary ===")
    print("✅ Role operations with comprehensive logging")
    print("✅ Permission management with security events")
    print("✅ RBAC assignments with audit trails")
    print("✅ Error handling and logging")
    print("✅ Security event logging for suspicious activities")
    print("✅ Complete audit trail for compliance")
    
    print(f"\n=== Log Files ===")
    print("Check the 'logs/' directory for detailed RBAC operation logs")
    print("- All RBAC operations are logged with structured data")
    print("- Security-sensitive operations trigger security events")
    print("- Error conditions are properly logged with context")
    print("- Audit trail provides complete operation history")
    
    print(f"\n=== Key Features Demonstrated ===")
    print("🔐 Security-aware logging for all RBAC operations")
    print("📊 Structured logging with operation context")  
    print("🚨 Automatic security event generation")
    print("📝 Comprehensive audit trail")
    print("⚠️  Error handling with detailed logging")
    print("👤 User context tracking (who did what)")
    print("🎯 Operation-specific logging (create, update, delete, assign)")
    
    print("\nRBAC logging demo completed!")


if __name__ == '__main__':
    asyncio.run(main()) 