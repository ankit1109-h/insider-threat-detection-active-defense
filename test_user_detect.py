import sys, os
sys.path.insert(0, 'vm_agent')

from monitor_files import load_access_policy, compute_user_restrictions

policy = load_access_policy()
print(f"Access Policy loaded: {len(policy)} folders")
for folder, roles in policy.items():
    print(f"  {folder} -> allowed: {roles}")

print()

# Test for each role
test_roles = [
    ('Administrator', 'high'),
    ('Human Resources', 'medium'),
    ('Finance', 'high'),
    ('Engineering', 'medium'),
    ('Employee', 'low'),   # New unknown user
]

for role, clearance in test_roles:
    restricted = compute_user_restrictions(role, clearance, policy)
    print(f"\nRole: {role} (clearance={clearance})")
    if restricted:
        print(f"  RESTRICTED folders: {list(restricted.keys())}")
    else:
        print(f"  FULL ACCESS - no folder restrictions")
