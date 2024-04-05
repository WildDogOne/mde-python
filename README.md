# mde-python

Microsoft Defender for Endpoint Integration

### Usage
```
from mde.mde import defender
mde_config = {
    "api_url": "https://graph.microsoft.com/beta/",
    "tenant_id": "XXX",
    "client_id": "XXX",
    "client_secret": "XXX",
}

mde = defender(mde_configs)

## Get Inventory
response =  mde.get("/api/Machines/BrowserExtensionsInventoryByMachine")
```