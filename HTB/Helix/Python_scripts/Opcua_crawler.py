
```python
import asyncio
from asyncua import Client, ua

URL = "opc.tcp://127.0.0.1:4840/helix/"

async def writable(node):
    try:
        ual = await node.read_attribute(ua.AttributeIds.UserAccessLevel)
        bits = int(ual.Value.Value)
    except Exception:
        al = await node.read_attribute(ua.AttributeIds.AccessLevel)
        bits = int(al.Value.Value)
    return bool(bits & 0x02)

async def walk(node, path):
    try:
        kids = await node.get_children()
    except Exception:
        return
    for k in kids:
        try:
            name = (await k.read_browse_name()).Name
        except Exception:
            name = str(k.nodeid)
        new_path = f"{path}.{name}"
        try:
            nc = await k.read_node_class()
        except Exception:
            nc = None
        if nc == ua.NodeClass.Variable:
            marker = "[W]" if await writable(k) else "[R]"
            try:
                val = await k.read_value()
            except Exception:
                val = "?"
            print(f"{marker} {new_path} = {val}  -> {k.nodeid}")
        await walk(k, new_path)

async def main():
    async with Client(URL) as c:
        plant = await c.nodes.objects.get_child(["2:Plant"])
        await walk(plant, "Plant")

asyncio.run(main())
```