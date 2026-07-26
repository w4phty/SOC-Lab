import uuid

for i in range(1,30):
    sigma_uuid = "id: " + str(uuid.uuid4())
    rule_id = f"x_rule_id: SPL-{i:02d}"
    print(f"\nRule {i:02d}")
    print(sigma_uuid)
    print(rule_id)
