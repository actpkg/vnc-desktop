GET {{baseurl}}/info
HTTP 200
[Asserts]
jsonpath "$.std.name" == "vnc-desktop"
jsonpath "$.std.version" isString
