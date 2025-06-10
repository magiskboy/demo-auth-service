from typing import List, Optional
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import LoggerMixin, log_security_event
from .models import Role, Permission, UserRole, RolePermission
from .schemas import RoleCreate, PermissionCreate, RoleUpdate, RoleFilter, PermissionUpdate, PermissionFilter


class RoleService(LoggerMixin):
    """Service for managing roles with comprehensive logging."""
    
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db
        self.logger.info("RoleService initialized")

    async def create_role(self, role: RoleCreate, user_id: Optional[str] = None) -> Role:
        """Create a new role with logging."""
        self.logger.info(
            "Creating new role",
            extra={
                'role_name': role.name,
                'role_description': role.description,
                'user_id': user_id,
                'operation': 'create_role'
            }
        )
        
        try:
            role_obj = Role(name=role.name, description=role.description or "")
            self.db.add(role_obj)
            await self.db.commit()
            await self.db.refresh(role_obj)
            
            # Log security event for role creation
            log_security_event(
                'role_created',
                user_id=user_id,
                details=f"Role '{role.name}' created",
                role_id=str(role_obj.id),
                role_name=role.name
            )
            
            self.logger.info(
                "Role created successfully",
                extra={
                    'role_id': str(role_obj.id),
                    'role_name': role.name,
                    'user_id': user_id,
                    'operation': 'create_role'
                }
            )
            
            return role_obj
            
        except Exception as e:
            self.logger.error(
                "Failed to create role",
                extra={
                    'role_name': role.name,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'create_role'
                },
                exc_info=True
            )
            raise
    
    async def get_role(self, role_id: str, user_id: Optional[str] = None) -> Optional[Role]:
        """Get role by ID with logging."""
        self.logger.debug(
            "Retrieving role by ID",
            extra={
                'role_id': role_id,
                'user_id': user_id,
                'operation': 'get_role'
            }
        )
        
        try:
            role = await self.db.get(Role, role_id)
            
            if role:
                self.logger.debug(
                    "Role found",
                    extra={
                        'role_id': role_id,
                        'role_name': role.name,
                        'user_id': user_id,
                        'operation': 'get_role'
                    }
                )
            else:
                self.logger.warning(
                    "Role not found",
                    extra={
                        'role_id': role_id,
                        'user_id': user_id,
                        'operation': 'get_role'
                    }
                )
            
            return role
            
        except Exception as e:
            self.logger.error(
                "Failed to retrieve role",
                extra={
                    'role_id': role_id,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'get_role'
                },
                exc_info=True
            )
            raise
    
    async def update_role(self, role_update: RoleUpdate, user_id: Optional[str] = None) -> Role:
        """Update role with logging."""
        self.logger.info(
            "Updating role",
            extra={
                'role_id': role_update.id,
                'new_name': role_update.name,
                'new_description': role_update.description,
                'user_id': user_id,
                'operation': 'update_role'
            }
        )
        
        try:
            role = await self.get_role(role_update.id, user_id)
            if not role:
                self.logger.warning(
                    "Attempted to update non-existent role",
                    extra={
                        'role_id': role_update.id,
                        'user_id': user_id,
                        'operation': 'update_role'
                    }
                )
                raise ValueError("Role not found")
            
            # Log the changes
            old_name = role.name
            old_description = role.description
            
            role.name = role_update.name
            role.description = role_update.description or ""
            self.db.add(role)
            await self.db.commit()
            await self.db.refresh(role)
            
            # Log security event for role modification
            log_security_event(
                'role_updated',
                user_id=user_id,
                details=f"Role '{old_name}' updated to '{role.name}'",
                role_id=str(role.id),
                old_name=old_name,
                new_name=role.name,
                old_description=old_description,
                new_description=role.description
            )
            
            self.logger.info(
                "Role updated successfully",
                extra={
                    'role_id': str(role.id),
                    'old_name': old_name,
                    'new_name': role.name,
                    'user_id': user_id,
                    'operation': 'update_role'
                }
            )
            
            return role
            
        except Exception as e:
            self.logger.error(
                "Failed to update role",
                extra={
                    'role_id': role_update.id,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'update_role'
                },
                exc_info=True
            )
            raise
    
    async def get_roles(self, filter: RoleFilter, user_id: Optional[str] = None) -> List[Role]:
        """Get roles with filtering and logging."""
        self.logger.debug(
            "Retrieving roles with filter",
            extra={
                'filter_name': filter.name if filter else None,
                'filter_description': filter.description if filter else None,
                'user_id': user_id,
                'operation': 'get_roles'
            }
        )
        
        try:
            query = select(Role)
            if filter and filter.name:
                query = query.where(Role.name == filter.name)
            if filter and filter.description:
                query = query.where(Role.description == filter.description)
            
            result = await self.db.execute(query)
            roles = list(result.scalars().all())
            
            self.logger.debug(
                "Roles retrieved successfully",
                extra={
                    'role_count': len(roles),
                    'user_id': user_id,
                    'operation': 'get_roles'
                }
            )
            
            return roles
            
        except Exception as e:
            self.logger.error(
                "Failed to retrieve roles",
                extra={
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'get_roles'
                },
                exc_info=True
            )
            raise

    async def delete_role(self, role_id: str, user_id: Optional[str] = None) -> bool:
        """Delete role with logging."""
        self.logger.info(
            "Deleting role",
            extra={
                'role_id': role_id,
                'user_id': user_id,
                'operation': 'delete_role'
            }
        )
        
        try:
            role = await self.get_role(role_id, user_id)
            if not role:
                self.logger.warning(
                    "Attempted to delete non-existent role",
                    extra={
                        'role_id': role_id,
                        'user_id': user_id,
                        'operation': 'delete_role'
                    }
                )
                return False
            
            role_name = role.name
            await self.db.delete(role)
            await self.db.commit()
            
            # Log security event for role deletion
            log_security_event(
                'role_deleted',
                user_id=user_id,
                details=f"Role '{role_name}' deleted",
                role_id=role_id,
                role_name=role_name
            )
            
            self.logger.info(
                "Role deleted successfully",
                extra={
                    'role_id': role_id,
                    'role_name': role_name,
                    'user_id': user_id,
                    'operation': 'delete_role'
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to delete role",
                extra={
                    'role_id': role_id,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'delete_role'
                },
                exc_info=True
            )
            raise


class PermissionService(LoggerMixin):
    """Service for managing permissions with comprehensive logging."""
    
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db
        self.logger.info("PermissionService initialized")

    async def create_permission(self, permission: PermissionCreate, user_id: Optional[str] = None) -> Permission:
        """Create a new permission with logging."""
        self.logger.info(
            "Creating new permission",
            extra={
                'permission_name': permission.name,
                'permission_description': permission.description,
                'user_id': user_id,
                'operation': 'create_permission'
            }
        )
        
        try:
            permission_obj = Permission(name=permission.name, description=permission.description or "")
            self.db.add(permission_obj)
            await self.db.commit()
            await self.db.refresh(permission_obj)
            
            # Log security event for permission creation
            log_security_event(
                'permission_created',
                user_id=user_id,
                details=f"Permission '{permission.name}' created",
                permission_id=str(permission_obj.id),
                permission_name=permission.name
            )
            
            self.logger.info(
                "Permission created successfully",
                extra={
                    'permission_id': str(permission_obj.id),
                    'permission_name': permission.name,
                    'user_id': user_id,
                    'operation': 'create_permission'
                }
            )
            
            return permission_obj
            
        except Exception as e:
            self.logger.error(
                "Failed to create permission",
                extra={
                    'permission_name': permission.name,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'create_permission'
                },
                exc_info=True
            )
            raise
    
    async def get_permission(self, permission_id: str, user_id: Optional[str] = None) -> Optional[Permission]:
        """Get permission by ID with logging."""
        self.logger.debug(
            "Retrieving permission by ID",
            extra={
                'permission_id': permission_id,
                'user_id': user_id,
                'operation': 'get_permission'
            }
        )
        
        try:
            permission = await self.db.get(Permission, permission_id)
            
            if permission:
                self.logger.debug(
                    "Permission found",
                    extra={
                        'permission_id': permission_id,
                        'permission_name': permission.name,
                        'user_id': user_id,
                        'operation': 'get_permission'
                    }
                )
            else:
                self.logger.warning(
                    "Permission not found",
                    extra={
                        'permission_id': permission_id,
                        'user_id': user_id,
                        'operation': 'get_permission'
                    }
                )
            
            return permission
            
        except Exception as e:
            self.logger.error(
                "Failed to retrieve permission",
                extra={
                    'permission_id': permission_id,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'get_permission'
                },
                exc_info=True
            )
            raise
    
    async def update_permission(self, permission_update: PermissionUpdate, user_id: Optional[str] = None) -> Permission:
        """Update permission with logging."""
        self.logger.info(
            "Updating permission",
            extra={
                'permission_id': permission_update.id,
                'new_name': permission_update.name,
                'new_description': permission_update.description,
                'user_id': user_id,
                'operation': 'update_permission'
            }
        )
        
        try:
            permission = await self.get_permission(permission_update.id, user_id)
            if not permission:
                self.logger.warning(
                    "Attempted to update non-existent permission",
                    extra={
                        'permission_id': permission_update.id,
                        'user_id': user_id,
                        'operation': 'update_permission'
                    }
                )
                raise ValueError("Permission not found")
            
            # Log the changes
            old_name = permission.name
            old_description = permission.description
            
            permission.name = permission_update.name
            permission.description = permission_update.description or ""
            self.db.add(permission)
            await self.db.commit()
            await self.db.refresh(permission)
            
            # Log security event for permission modification
            log_security_event(
                'permission_updated',
                user_id=user_id,
                details=f"Permission '{old_name}' updated to '{permission.name}'",
                permission_id=str(permission.id),
                old_name=old_name,
                new_name=permission.name,
                old_description=old_description,
                new_description=permission.description
            )
            
            self.logger.info(
                "Permission updated successfully",
                extra={
                    'permission_id': str(permission.id),
                    'old_name': old_name,
                    'new_name': permission.name,
                    'user_id': user_id,
                    'operation': 'update_permission'
                }
            )
            
            return permission
            
        except Exception as e:
            self.logger.error(
                "Failed to update permission",
                extra={
                    'permission_id': permission_update.id,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'update_permission'
                },
                exc_info=True
            )
            raise
    
    async def get_permissions(self, filter: PermissionFilter, user_id: Optional[str] = None) -> List[Permission]:
        """Get permissions with filtering and logging."""
        self.logger.debug(
            "Retrieving permissions with filter",
            extra={
                'filter_name': filter.name if filter else None,
                'filter_description': filter.description if filter else None,
                'user_id': user_id,
                'operation': 'get_permissions'
            }
        )
        
        try:
            query = select(Permission)
            if filter and filter.name:
                query = query.where(Permission.name == filter.name)
            if filter and filter.description:
                query = query.where(Permission.description == filter.description)
                
            result = await self.db.execute(query)
            permissions = list(result.scalars().all())
            
            self.logger.debug(
                "Permissions retrieved successfully",
                extra={
                    'permission_count': len(permissions),
                    'user_id': user_id,
                    'operation': 'get_permissions'
                }
            )
            
            return permissions
            
        except Exception as e:
            self.logger.error(
                "Failed to retrieve permissions",
                extra={
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'get_permissions'
                },
                exc_info=True
            )
            raise

    async def delete_permission(self, permission_id: str, user_id: Optional[str] = None) -> bool:
        """Delete permission with logging."""
        self.logger.info(
            "Deleting permission",
            extra={
                'permission_id': permission_id,
                'user_id': user_id,
                'operation': 'delete_permission'
            }
        )
        
        try:
            permission = await self.get_permission(permission_id, user_id)
            if not permission:
                self.logger.warning(
                    "Attempted to delete non-existent permission",
                    extra={
                        'permission_id': permission_id,
                        'user_id': user_id,
                        'operation': 'delete_permission'
                    }
                )
                return False
            
            permission_name = permission.name
            await self.db.delete(permission)
            await self.db.commit()
            
            # Log security event for permission deletion
            log_security_event(
                'permission_deleted',
                user_id=user_id,
                details=f"Permission '{permission_name}' deleted",
                permission_id=permission_id,
                permission_name=permission_name
            )
            
            self.logger.info(
                "Permission deleted successfully",
                extra={
                    'permission_id': permission_id,
                    'permission_name': permission_name,
                    'user_id': user_id,
                    'operation': 'delete_permission'
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to delete permission",
                extra={
                    'permission_id': permission_id,
                    'user_id': user_id,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'delete_permission'
                },
                exc_info=True
            )
            raise


class RBACService(LoggerMixin):
    """Service for RBAC operations (role assignments) with comprehensive logging."""
    
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db
        self.logger.info("RBACService initialized")

    async def assign_role_to_user(self, user_id: str, role_id: str, assigned_by: Optional[str] = None) -> UserRole:
        """Assign role to user with security logging."""
        self.logger.info(
            "Assigning role to user",
            extra={
                'target_user_id': user_id,
                'role_id': role_id,
                'assigned_by': assigned_by,
                'operation': 'assign_role_to_user'
            }
        )
        
        try:
            # Check if assignment already exists
            existing_query = select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == role_id
            )
            existing_result = await self.db.execute(existing_query)
            existing_assignment = existing_result.scalar_one_or_none()
            
            if existing_assignment:
                self.logger.warning(
                    "Role already assigned to user",
                    extra={
                        'target_user_id': user_id,
                        'role_id': role_id,
                        'assigned_by': assigned_by,
                        'operation': 'assign_role_to_user'
                    }
                )
                return existing_assignment
            
            user_role = UserRole(user_id=user_id, role_id=role_id)
            self.db.add(user_role)
            await self.db.commit()
            await self.db.refresh(user_role)
            
            # Log critical security event for role assignment
            log_security_event(
                'role_assigned',
                user_id=assigned_by,
                details=f"Role {role_id} assigned to user {user_id}",
                target_user_id=user_id,
                role_id=role_id,
                assignment_id=str(user_role.id)
            )
            
            self.logger.info(
                "Role assigned to user successfully",
                extra={
                    'assignment_id': str(user_role.id),
                    'target_user_id': user_id,
                    'role_id': role_id,
                    'assigned_by': assigned_by,
                    'operation': 'assign_role_to_user'
                }
            )
            
            return user_role
            
        except Exception as e:
            self.logger.error(
                "Failed to assign role to user",
                extra={
                    'target_user_id': user_id,
                    'role_id': role_id,
                    'assigned_by': assigned_by,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'assign_role_to_user'
                },
                exc_info=True
            )
            raise
    
    async def assign_permission_to_role(self, role_id: str, permission_id: str, assigned_by: Optional[str] = None) -> RolePermission:
        """Assign permission to role with security logging."""
        self.logger.info(
            "Assigning permission to role",
            extra={
                'role_id': role_id,
                'permission_id': permission_id,
                'assigned_by': assigned_by,
                'operation': 'assign_permission_to_role'
            }
        )
        
        try:
            # Check if assignment already exists
            existing_query = select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id
            )
            existing_result = await self.db.execute(existing_query)
            existing_assignment = existing_result.scalar_one_or_none()
            
            if existing_assignment:
                self.logger.warning(
                    "Permission already assigned to role",
                    extra={
                        'role_id': role_id,
                        'permission_id': permission_id,
                        'assigned_by': assigned_by,
                        'operation': 'assign_permission_to_role'
                    }
                )
                return existing_assignment
            
            role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
            self.db.add(role_permission)
            await self.db.commit()
            await self.db.refresh(role_permission)
            
            # Log critical security event for permission assignment
            log_security_event(
                'permission_assigned',
                user_id=assigned_by,
                details=f"Permission {permission_id} assigned to role {role_id}",
                role_id=role_id,
                permission_id=permission_id,
                assignment_id=str(role_permission.id)
            )
            
            self.logger.info(
                "Permission assigned to role successfully",
                extra={
                    'assignment_id': str(role_permission.id),
                    'role_id': role_id,
                    'permission_id': permission_id,
                    'assigned_by': assigned_by,
                    'operation': 'assign_permission_to_role'
                }
            )
            
            return role_permission
            
        except Exception as e:
            self.logger.error(
                "Failed to assign permission to role",
                extra={
                    'role_id': role_id,
                    'permission_id': permission_id,
                    'assigned_by': assigned_by,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'assign_permission_to_role'
                },
                exc_info=True
            )
            raise

    async def revoke_role_from_user(self, user_id: str, role_id: str, revoked_by: Optional[str] = None) -> bool:
        """Revoke role from user with security logging."""
        self.logger.info(
            "Revoking role from user",
            extra={
                'target_user_id': user_id,
                'role_id': role_id,
                'revoked_by': revoked_by,
                'operation': 'revoke_role_from_user'
            }
        )
        
        try:
            # Find the assignment
            query = select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == role_id
            )
            result = await self.db.execute(query)
            user_role = result.scalar_one_or_none()
            
            if not user_role:
                self.logger.warning(
                    "Attempted to revoke non-existent role assignment",
                    extra={
                        'target_user_id': user_id,
                        'role_id': role_id,
                        'revoked_by': revoked_by,
                        'operation': 'revoke_role_from_user'
                    }
                )
                return False
            
            await self.db.delete(user_role)
            await self.db.commit()
            
            # Log critical security event for role revocation
            log_security_event(
                'role_revoked',
                user_id=revoked_by,
                details=f"Role {role_id} revoked from user {user_id}",
                target_user_id=user_id,
                role_id=role_id
            )
            
            self.logger.info(
                "Role revoked from user successfully",
                extra={
                    'target_user_id': user_id,
                    'role_id': role_id,
                    'revoked_by': revoked_by,
                    'operation': 'revoke_role_from_user'
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to revoke role from user",
                extra={
                    'target_user_id': user_id,
                    'role_id': role_id,
                    'revoked_by': revoked_by,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'revoke_role_from_user'
                },
                exc_info=True
            )
            raise

    async def revoke_permission_from_role(self, role_id: str, permission_id: str, revoked_by: Optional[str] = None) -> bool:
        """Revoke permission from role with security logging."""
        self.logger.info(
            "Revoking permission from role",
            extra={
                'role_id': role_id,
                'permission_id': permission_id,
                'revoked_by': revoked_by,
                'operation': 'revoke_permission_from_role'
            }
        )
        
        try:
            # Find the assignment
            query = select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id
            )
            result = await self.db.execute(query)
            role_permission = result.scalar_one_or_none()
            
            if not role_permission:
                self.logger.warning(
                    "Attempted to revoke non-existent permission assignment",
                    extra={
                        'role_id': role_id,
                        'permission_id': permission_id,
                        'revoked_by': revoked_by,
                        'operation': 'revoke_permission_from_role'
                    }
                )
                return False
            
            await self.db.delete(role_permission)
            await self.db.commit()
            
            # Log critical security event for permission revocation
            log_security_event(
                'permission_revoked',
                user_id=revoked_by,
                details=f"Permission {permission_id} revoked from role {role_id}",
                role_id=role_id,
                permission_id=permission_id
            )
            
            self.logger.info(
                "Permission revoked from role successfully",
                extra={
                    'role_id': role_id,
                    'permission_id': permission_id,
                    'revoked_by': revoked_by,
                    'operation': 'revoke_permission_from_role'
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to revoke permission from role",
                extra={
                    'role_id': role_id,
                    'permission_id': permission_id,
                    'revoked_by': revoked_by,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'revoke_permission_from_role'
                },
                exc_info=True
            )
            raise

    async def get_user_roles(self, user_id: str, requested_by: Optional[str] = None) -> List[UserRole]:
        """Get roles assigned to a user with logging."""
        self.logger.debug(
            "Retrieving user roles",
            extra={
                'target_user_id': user_id,
                'requested_by': requested_by,
                'operation': 'get_user_roles'
            }
        )
        
        try:
            query = select(UserRole).where(UserRole.user_id == user_id)
            result = await self.db.execute(query)
            user_roles = list(result.scalars().all())
            
            self.logger.debug(
                "User roles retrieved successfully",
                extra={
                    'target_user_id': user_id,
                    'role_count': len(user_roles),
                    'requested_by': requested_by,
                    'operation': 'get_user_roles'
                }
            )
            
            return user_roles
            
        except Exception as e:
            self.logger.error(
                "Failed to retrieve user roles",
                extra={
                    'target_user_id': user_id,
                    'requested_by': requested_by,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'get_user_roles'
                },
                exc_info=True
            )
            raise

    async def get_role_permissions(self, role_id: str, requested_by: Optional[str] = None) -> List[RolePermission]:
        """Get permissions assigned to a role with logging."""
        self.logger.debug(
            "Retrieving role permissions",
            extra={
                'role_id': role_id,
                'requested_by': requested_by,
                'operation': 'get_role_permissions'
            }
        )
        
        try:
            query = select(RolePermission).where(RolePermission.role_id == role_id)
            result = await self.db.execute(query)
            role_permissions = list(result.scalars().all())
            
            self.logger.debug(
                "Role permissions retrieved successfully",
                extra={
                    'role_id': role_id,
                    'permission_count': len(role_permissions),
                    'requested_by': requested_by,
                    'operation': 'get_role_permissions'
                }
            )
            
            return role_permissions
            
        except Exception as e:
            self.logger.error(
                "Failed to retrieve role permissions",
                extra={
                    'role_id': role_id,
                    'requested_by': requested_by,
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'operation': 'get_role_permissions'
                },
                exc_info=True
            )
            raise