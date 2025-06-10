import httpx
from typing import Dict, List

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

class SeedDataGenerator:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.api_base = f"{base_url}/api/v1"
        self.session = httpx.Client()
        
    def check_health(self):
        """Check if the API is healthy"""
        try:
            response = self.session.get(f"{self.base_url}/healthz")
            response.raise_for_status()
            print("✅ API is healthy")
            return True
        except httpx.RequestError as e:
            print(f"❌ API health check failed: {e}")
            return False
    
    def create_permissions(self) -> Dict[str, str]:
        """Create permissions and return a mapping of permission names to IDs"""
        permissions = [
            {
                "name": "GET:/api/v1/users",
                "description": "Read users list"
            },
            {
                "name": "POST:/api/v1/users",
                "description": "Create users"
            },
            {
                "name": "PUT:/api/v1/users/*",
                "description": "Update users"
            },
            {
                "name": "DELETE:/api/v1/users/*",
                "description": "Delete users"
            },
            {
                "name": "GET:/api/v1/admin/roles",
                "description": "Read roles"
            },
            {
                "name": "POST:/api/v1/admin/roles",
                "description": "Create roles"
            },
            {
                "name": "PUT:/api/v1/admin/roles/*",
                "description": "Update roles"
            },
            {
                "name": "GET:/api/v1/admin/permissions",
                "description": "Read permissions"
            },
            {
                "name": "POST:/api/v1/admin/permissions",
                "description": "Create permissions"
            },
            {
                "name": "PUT:/api/v1/admin/permissions/*",
                "description": "Update permissions"
            }
        ]
        
        permission_map = {}
        print("\n📋 Creating permissions...")
        
        for permission in permissions:
            try:
                response = self.session.post(
                    f"{self.api_base}/admin/permissions",
                    json=permission
                )
                if response.status_code == 201:
                    data = response.json()
                    permission_map[permission["name"]] = data["id"]
                    print(f"  ✅ Created permission: {permission['name']}")
                else:
                    print(f"  ❌ Failed to create permission {permission['name']}: {response.text}")
            except httpx.RequestError as e:
                print(f"  ❌ Error creating permission {permission['name']}: {e}")
        
        return permission_map
    
    def create_roles(self, permission_map: Dict[str, str]) -> Dict[str, str]:
        """Create roles and return a mapping of role names to IDs"""
        roles = [
            {
                "name": "admin",
                "description": "Administrator with full access",
                "permissions": [
                    "GET:/api/v1/users",
                    "POST:/api/v1/users", 
                    "PUT:/api/v1/users/*",
                    "DELETE:/api/v1/users/*",
                    "GET:/api/v1/admin/roles",
                    "POST:/api/v1/admin/roles",
                    "PUT:/api/v1/admin/roles/*",
                    "GET:/api/v1/admin/permissions",
                    "POST:/api/v1/admin/permissions",
                    "PUT:/api/v1/admin/permissions/*"
                ]
            },
            {
                "name": "user_manager",
                "description": "Can manage users but not roles/permissions",
                "permissions": [
                    "GET:/api/v1/users",
                    "POST:/api/v1/users",
                    "PUT:/api/v1/users/*"
                ]
            },
            {
                "name": "viewer",
                "description": "Read-only access to users",
                "permissions": [
                    "GET:/api/v1/users"
                ]
            }
        ]
        
        role_map = {}
        print("\n👥 Creating roles...")
        
        for role in roles:
            try:
                # Create the role
                role_data = {
                    "name": role["name"],
                    "description": role["description"]
                }
                response = self.session.post(
                    f"{self.api_base}/admin/roles",
                    json=role_data
                )
                
                if response.status_code == 201:
                    data = response.json()
                    role_id = data["id"]
                    role_map[role["name"]] = role_id
                    print(f"  ✅ Created role: {role['name']}")
                    
                    # Assign permissions to the role
                    for permission_name in role["permissions"]:
                        if permission_name in permission_map:
                            try:
                                perm_response = self.session.post(
                                    f"{self.api_base}/admin/roles/{role_id}/permissions",
                                    json={
                                        "role_id": role_id,
                                        "permission_id": permission_map[permission_name]
                                    }
                                )
                                if perm_response.status_code == 201:
                                    print(f"    ✅ Assigned permission {permission_name} to {role['name']}")
                                else:
                                    print(f"    ❌ Failed to assign permission {permission_name} to {role['name']}: {perm_response.text}")
                            except httpx.RequestError as e:
                                print(f"    ❌ Error assigning permission {permission_name} to {role['name']}: {e}")
                else:
                    print(f"  ❌ Failed to create role {role['name']}: {response.text}")
            except httpx.RequestError as e:
                print(f"  ❌ Error creating role {role['name']}: {e}")
        
        return role_map
    
    def create_users(self, role_map: Dict[str, str]) -> List[str]:
        """Create users and return list of user IDs"""
        users = [
            {
                "email": "admin@example.com",
                "name": "System Administrator",
                "password": "admin123",
                "roles": ["admin"]
            },
            {
                "email": "manager@example.com", 
                "name": "User Manager",
                "password": "manager123",
                "roles": ["user_manager"]
            },
            {
                "email": "viewer@example.com",
                "name": "Read Only User", 
                "password": "viewer123",
                "roles": ["viewer"]
            },
            {
                "email": "john.doe@example.com",
                "name": "John Doe",
                "password": "user123",
                "roles": ["viewer"]
            },
            {
                "email": "jane.smith@example.com",
                "name": "Jane Smith",
                "password": "user123", 
                "roles": ["viewer"]
            }
        ]
        
        user_ids = []
        print("\n👤 Creating users...")
        
        for user in users:
            try:
                # Create the user
                user_data = {
                    "email": user["email"],
                    "name": user["name"],
                    "password": user["password"]
                }
                response = self.session.post(
                    f"{self.api_base}/admin/users",
                    json=user_data
                )
                
                if response.status_code == 201:
                    data = response.json()
                    user_id = data["id"]
                    user_ids.append(user_id)
                    print(f"  ✅ Created user: {user['name']} ({user['email']})")
                    
                    # Assign roles to the user
                    for role_name in user["roles"]:
                        if role_name in role_map:
                            try:
                                role_response = self.session.post(
                                    f"{self.api_base}/admin/users/{user_id}/roles",
                                    json={
                                        "user_id": user_id,
                                        "role_id": role_map[role_name]
                                    }
                                )
                                if role_response.status_code == 201:
                                    print(f"    ✅ Assigned role {role_name} to {user['name']}")
                                else:
                                    print(f"    ❌ Failed to assign role {role_name} to {user['name']}: {role_response.text}")
                            except httpx.RequestError as e:
                                print(f"    ❌ Error assigning role {role_name} to {user['name']}: {e}")
                else:
                    print(f"  ❌ Failed to create user {user['name']}: {response.text}")
            except httpx.RequestError as e:
                print(f"  ❌ Error creating user {user['name']}: {e}")
        
        return user_ids
    
    def verify_seed_data(self):
        """Verify that the seed data was created successfully"""
        print("\n🔍 Verifying seed data...")
        
        try:
            # Check users
            users_response = self.session.get(f"{self.api_base}/admin/users")
            if users_response.status_code == 200:
                users = users_response.json()
                print(f"  ✅ Found {len(users)} users")
            else:
                print(f"  ❌ Failed to fetch users: {users_response.text}")
        except httpx.RequestError as e:
            print(f"  ❌ Error fetching users: {e}")
            
        try:
            # Check roles
            roles_response = self.session.get(f"{self.api_base}/admin/roles")
            if roles_response.status_code == 200:
                roles = roles_response.json()
                print(f"  ✅ Found {len(roles)} roles")
            else:
                print(f"  ❌ Failed to fetch roles: {roles_response.text}")
        except httpx.RequestError as e:
            print(f"  ❌ Error fetching roles: {e}")
            
        try:
            # Check permissions
            permissions_response = self.session.get(f"{self.api_base}/admin/permissions")
            if permissions_response.status_code == 200:
                permissions = permissions_response.json()
                print(f"  ✅ Found {len(permissions)} permissions")
            else:
                print(f"  ❌ Failed to fetch permissions: {permissions_response.text}")
        except httpx.RequestError as e:
            print(f"  ❌ Error fetching permissions: {e}")
    
    def run(self):
        """Run the complete seed data generation process"""
        print("🌱 Starting seed data generation...")
        
        # Check if API is healthy
        if not self.check_health():
            print("❌ Cannot proceed without healthy API connection")
            return False
        
        # Create permissions first
        permission_map = self.create_permissions()
        if not permission_map:
            print("❌ Failed to create permissions")
            return False
        
        # Create roles with permission assignments
        role_map = self.create_roles(permission_map)
        if not role_map:
            print("❌ Failed to create roles")
            return False
        
        # Create users with role assignments  
        user_ids = self.create_users(role_map)
        if not user_ids:
            print("❌ Failed to create users")
            return False
        
        # Verify everything was created
        self.verify_seed_data()
        
        print("\n🎉 Seed data generation completed successfully!")
        print("\n📝 Summary:")
        print(f"   • {len(permission_map)} permissions created")
        print(f"   • {len(role_map)} roles created")
        print(f"   • {len(user_ids)} users created")
        print("\n🔐 Test users created:")
        print("   • admin@example.com (password: admin123) - Full admin access")
        print("   • manager@example.com (password: manager123) - User management access")
        print("   • viewer@example.com (password: viewer123) - Read-only access")
        print("   • john.doe@example.com (password: user123) - Read-only access")
        print("   • jane.smith@example.com (password: user123) - Read-only access")
        
        return True


def main():
    """Main function to run seed data generation"""
    seeder = SeedDataGenerator()
    success = seeder.run()
    
    if not success:
        print("\n❌ Seed data generation failed. Please check the error messages above.")
        exit(1)
    else:
        print("\n✅ Seed data generation completed successfully!")


if __name__ == "__main__":
    main()