async def test_component_exposes_its_tools(client):
    tools = await client.list_tools()
    assert len(tools) >= 1
