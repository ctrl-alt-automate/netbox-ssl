#!/usr/bin/env python3
"""
Create test data for NetBox SSL Plugin development.

This script creates sample devices, VMs, and services for testing
the certificate assignment workflow.

Run inside NetBox container:
    docker exec -it netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py shell < /opt/netbox/netbox/netbox_ssl/scripts/create_test_data.py

Or via nbshell:
    docker exec -it netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py nbshell
    >>> exec(open('/opt/netbox/netbox/netbox_ssl/scripts/create_test_data.py').read())
"""

from django.contrib.contenttypes.models import ContentType

# Import NetBox models
from dcim.models import Site, DeviceRole, DeviceType, Manufacturer, Device
from virtualization.models import Cluster, ClusterType, VirtualMachine
from ipam.models import Service
from tenancy.models import Tenant

print("=" * 60)
print("Creating test data for NetBox SSL Plugin")
print("=" * 60)

# ============================================================
# TENANTS
# ============================================================
print("\n[1/6] Creating Tenants...")

tenant_prod, _ = Tenant.objects.get_or_create(
    name="Production",
    defaults={"slug": "production", "description": "Production environment"}
)
tenant_dev, _ = Tenant.objects.get_or_create(
    name="Development",
    defaults={"slug": "development", "description": "Development environment"}
)
print(f"  ✓ Tenant: {tenant_prod.name}")
print(f"  ✓ Tenant: {tenant_dev.name}")

# ============================================================
# SITE
# ============================================================
print("\n[2/6] Creating Site...")

site, _ = Site.objects.get_or_create(
    name="Amsterdam DC1",
    defaults={"slug": "ams-dc1", "status": "active"}
)
print(f"  ✓ Site: {site.name}")

# ============================================================
# DEVICE INFRASTRUCTURE
# ============================================================
print("\n[3/6] Creating Device infrastructure...")

# Manufacturer
manufacturer, _ = Manufacturer.objects.get_or_create(
    name="Dell",
    defaults={"slug": "dell"}
)
print(f"  ✓ Manufacturer: {manufacturer.name}")

# Device Type
device_type, _ = DeviceType.objects.get_or_create(
    manufacturer=manufacturer,
    model="PowerEdge R640",
    defaults={"slug": "poweredge-r640"}
)
print(f"  ✓ Device Type: {device_type.model}")

# Device Role
role_web, _ = DeviceRole.objects.get_or_create(
    name="Web Server",
    defaults={"slug": "web-server", "color": "4caf50"}
)
role_db, _ = DeviceRole.objects.get_or_create(
    name="Database Server",
    defaults={"slug": "database-server", "color": "2196f3"}
)
role_lb, _ = DeviceRole.objects.get_or_create(
    name="Load Balancer",
    defaults={"slug": "load-balancer", "color": "ff9800"}
)
print(f"  ✓ Device Role: {role_web.name}")
print(f"  ✓ Device Role: {role_db.name}")
print(f"  ✓ Device Role: {role_lb.name}")

# ============================================================
# DEVICES
# ============================================================
print("\n[4/6] Creating Devices...")

devices_data = [
    {"name": "web-prod-01", "role": role_web, "tenant": tenant_prod},
    {"name": "web-prod-02", "role": role_web, "tenant": tenant_prod},
    {"name": "db-prod-01", "role": role_db, "tenant": tenant_prod},
    {"name": "lb-prod-01", "role": role_lb, "tenant": tenant_prod},
    {"name": "web-dev-01", "role": role_web, "tenant": tenant_dev},
    {"name": "db-dev-01", "role": role_db, "tenant": tenant_dev},
]

devices = {}
for data in devices_data:
    device, created = Device.objects.get_or_create(
        name=data["name"],
        defaults={
            "device_type": device_type,
            "role": data["role"],
            "site": site,
            "tenant": data["tenant"],
            "status": "active",
        }
    )
    devices[data["name"]] = device
    status = "created" if created else "exists"
    print(f"  ✓ Device: {device.name} ({data['tenant'].name}) [{status}]")

# ============================================================
# VIRTUAL MACHINES
# ============================================================
print("\n[5/6] Creating Virtual Machines...")

# Cluster Type
cluster_type, _ = ClusterType.objects.get_or_create(
    name="VMware vSphere",
    defaults={"slug": "vmware-vsphere"}
)

# Cluster (Note: site field removed in NetBox 4.5)
cluster, _ = Cluster.objects.get_or_create(
    name="vSphere Cluster 01",
    defaults={"type": cluster_type}
)
print(f"  ✓ Cluster: {cluster.name}")

vms_data = [
    {"name": "vm-web-prod-01", "tenant": tenant_prod},
    {"name": "vm-web-prod-02", "tenant": tenant_prod},
    {"name": "vm-api-prod-01", "tenant": tenant_prod},
    {"name": "vm-web-dev-01", "tenant": tenant_dev},
    {"name": "vm-api-dev-01", "tenant": tenant_dev},
]

vms = {}
for data in vms_data:
    vm, created = VirtualMachine.objects.get_or_create(
        name=data["name"],
        defaults={
            "cluster": cluster,
            "tenant": data["tenant"],
            "status": "active",
        }
    )
    vms[data["name"]] = vm
    status = "created" if created else "exists"
    print(f"  ✓ VM: {vm.name} ({data['tenant'].name}) [{status}]")

# ============================================================
# SERVICES
# ============================================================
print("\n[6/6] Creating Services...")

services_data = [
    # Production web servers
    {"name": "HTTPS", "port": 443, "protocol": "tcp", "device": devices["web-prod-01"]},
    {"name": "HTTPS", "port": 443, "protocol": "tcp", "device": devices["web-prod-02"]},
    {"name": "HTTP", "port": 80, "protocol": "tcp", "device": devices["web-prod-01"]},
    {"name": "HTTP", "port": 80, "protocol": "tcp", "device": devices["web-prod-02"]},
    # Production load balancer
    {"name": "HTTPS", "port": 443, "protocol": "tcp", "device": devices["lb-prod-01"]},
    {"name": "HTTPS-Admin", "port": 8443, "protocol": "tcp", "device": devices["lb-prod-01"]},
    # Production database
    {"name": "MySQL", "port": 3306, "protocol": "tcp", "device": devices["db-prod-01"]},
    {"name": "MySQL-SSL", "port": 3307, "protocol": "tcp", "device": devices["db-prod-01"]},
    # Development
    {"name": "HTTPS", "port": 443, "protocol": "tcp", "device": devices["web-dev-01"]},
    {"name": "MySQL", "port": 3306, "protocol": "tcp", "device": devices["db-dev-01"]},
    # VM services
    {"name": "HTTPS", "port": 443, "protocol": "tcp", "vm": vms["vm-web-prod-01"]},
    {"name": "HTTPS", "port": 443, "protocol": "tcp", "vm": vms["vm-web-prod-02"]},
    {"name": "API-HTTPS", "port": 8443, "protocol": "tcp", "vm": vms["vm-api-prod-01"]},
    {"name": "HTTPS", "port": 443, "protocol": "tcp", "vm": vms["vm-web-dev-01"]},
    {"name": "API-HTTPS", "port": 8443, "protocol": "tcp", "vm": vms["vm-api-dev-01"]},
]

for data in services_data:
    device = data.get("device")
    vm = data.get("vm")
    parent_obj = device if device else vm
    target = parent_obj.name

    # Get ContentType for parent object (NetBox 4.5 uses GenericForeignKey)
    parent_ct = ContentType.objects.get_for_model(parent_obj)

    # Build filter for checking if service exists
    filter_kwargs = {
        "name": data["name"],
        "protocol": data["protocol"],
        "parent_object_type": parent_ct,
        "parent_object_id": parent_obj.pk,
    }

    # Check if service already exists
    existing = Service.objects.filter(**filter_kwargs).first()
    if existing:
        print(f"  ✓ Service: {existing.name}:{data['port']} on {target} [exists]")
        continue

    # Create new service with GenericForeignKey pattern (NetBox 4.5)
    service = Service.objects.create(
        name=data["name"],
        protocol=data["protocol"],
        ports=[data["port"]],
        parent_object_type=parent_ct,
        parent_object_id=parent_obj.pk,
    )
    print(f"  ✓ Service: {service.name}:{data['port']} on {target} [created]")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("Test data creation complete!")
print("=" * 60)
print(f"""
Summary:
  - Tenants:          {Tenant.objects.count()}
  - Sites:            {Site.objects.count()}
  - Devices:          {Device.objects.count()}
  - Virtual Machines: {VirtualMachine.objects.count()}
  - Services:         {Service.objects.count()}

You can now test certificate assignments with:
  - Production devices: web-prod-01, web-prod-02, lb-prod-01, db-prod-01
  - Development devices: web-dev-01, db-dev-01
  - Production VMs: vm-web-prod-01, vm-web-prod-02, vm-api-prod-01
  - Development VMs: vm-web-dev-01, vm-api-dev-01

Each device/VM has services (HTTPS/443, HTTP/80, etc.) for port-level assignment.
Multi-tenancy is set up with Production and Development tenants.
""")
