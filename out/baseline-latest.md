# Agentic baseline - raw findings (no harness)

- **Run:** `base_65501a94d97f`
- **Target:** `langflow` @ `1.7.3`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Files in scope:** 26  |  **Tokens:** 213121  |  **Time:** 472.8s

> This is the output of the same model asked, in good faith, for the same rigor, but with nothing around it that enforces the rules. There is no evidence gate, no provenance, no bounded stop and no dedup between runs. Compare it with `findings/latest.md` from Foundry.

## Summary

| Verdict | Count |
|---|---|
| needs-review | 1 |
| true-positive | 14 |

## 1. Code injection via exec() with user-controlled flow vertex display names
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94

- **Location:** `src/backend/base/langflow/helpers/flow.py` (line 327)

generate_function_for_flow builds a Python function body string by interpolating vertex display_name values (line 296) into arg_mappings without sanitization, then compiles and exec()s the result with the module's full globals(). An authenticated user can create a flow whose input node display_name contains a quote character followed by arbitrary Python (e.g. '": __import__("os").system("id") #') to break out of the string literal in the generated tweaks dict and execute arbitrary OS commands with server-level privileges. This is reachable whenever a flow-as-tool component processes a flow whose inputs were attacker-crafted.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/helpers/flow.py:296` - resolves
  > `f'"{original_name}": {name}'`
- `src/backend/base/langflow/helpers/flow.py:327` - resolves
  > `exec(compiled_func, globals(), local_scope)  # noqa: S102`

---

## 2. Unauthenticated image file download — no auth dependency on /images endpoint
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862

- **Location:** `src/backend/base/langflow/api/v1/files.py` (line 138)

The download_image route carries no authentication dependency and performs no flow-ownership check. Any unauthenticated caller who knows a flow_id UUID and the stored filename can retrieve image files from Langflow storage. The companion download_file endpoint at line 106 correctly gates access via the get_flow dependency that checks current user ownership; this endpoint omits that gate entirely.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/files.py:138` - resolves
  > `@router.get("/images/{flow_id}/{file_name}")`
- `src/backend/base/langflow/api/v1/files.py:139` - resolves
  > `async def download_image(`
- `src/backend/base/langflow/api/v1/files.py:140` - resolves
  > `file_name: ValidatedFileName,`
- `src/backend/base/langflow/api/v1/files.py:141` - resolves
  > `flow_id: UUID,`

---

## 3. X-Forwarded-For spoofing bypasses local-only restriction on MCP config install
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-348

- **Location:** `src/backend/base/langflow/api/v1/mcp_projects.py` (line 693)

install_mcp_config is supposed to be callable only from localhost, but get_client_ip unconditionally trusts the X-Forwarded-For header. An authenticated remote attacker who sends X-Forwarded-For: 127.0.0.1 passes the is_local_ip check and can remotely invoke the endpoint, which reads and overwrites JSON config files on the server filesystem (e.g. ~/.cursor/mcp.json) for Cursor, Windsurf, or Claude — a write-to-filesystem primitive from the network.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/mcp_projects.py:670` - resolves
  > `forwarded_for = request.headers.get("X-Forwarded-For")`
- `src/backend/base/langflow/api/v1/mcp_projects.py:673` - resolves
  > `return forwarded_for.split(",")[0].strip()`
- `src/backend/base/langflow/api/v1/mcp_projects.py:693` - resolves
  > `if not is_local_ip(client_ip):`

---

## 4. Path traversal in knowledge-base delete allows shutil.rmtree on arbitrary server directories
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-22

- **Location:** `src/backend/base/langflow/api/v1/knowledge_bases.py` (line 400)

delete_knowledge_base constructs kb_path = kb_root_path / kb_user / kb_name where kb_name comes directly from the URL path parameter. Python's pathlib does not sanitise .. components in individual path segments, so an authenticated user passing kb_name=../../etc causes the constructed path to resolve outside the intended directory. The exists()/is_dir() guards follow symlinks and traversal, so a real target directory passes the check; shutil.rmtree then recursively deletes it. The bulk endpoint (line 422) has the same flaw via kb_path = kb_user_path / kb_name.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/knowledge_bases.py:394` - resolves
  > `kb_path = kb_root_path / kb_user / kb_name`
- `src/backend/base/langflow/api/v1/knowledge_bases.py:400` - resolves
  > `shutil.rmtree(kb_path)`

---

## 5. Path traversal in knowledge-base GET allows reading/probing arbitrary filesystem paths
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-22

- **Location:** `src/backend/base/langflow/api/v1/knowledge_bases.py` (line 359)

get_knowledge_base constructs the path from the unsanitised kb_name URL parameter (kb_path = kb_root_path / kb_user / kb_name) and then opens and reads JSON files, queries the Chroma vector store, and returns metadata about the resolved directory. An authenticated user can traverse to other users' knowledge-base directories (e.g. ../victim_user/secret_kb) or probe for the existence of server filesystem paths.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/knowledge_bases.py:359` - resolves
  > `kb_path = kb_root_path / kb_user / kb_name`

---

## 6. IDOR: any authenticated user can delete any other user's API key
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/api_key.py` (line 50)

delete_api_key_route requires only that the caller is an active user (via the dependencies list) but passes api_key_id directly to delete_api_key without checking that the key belongs to the requesting user. Because API key UUIDs are the sole access control, an authenticated user who discovers another user's api_key_id (e.g. through the monitor or a separate info-leak) can permanently revoke it.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/api_key.py:44` - resolves
  > `@router.delete("/{api_key_id}", dependencies=[Depends(auth_utils.get_current_active_user)])`
- `src/backend/base/langflow/api/v1/api_key.py:50` - resolves
  > `await delete_api_key(db, api_key_id)`

---

## 7. Arbitrary server-side Python execution via custom component endpoint
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-94

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` (line 878)

The /custom_component and /custom_component/update endpoints accept raw Python source code from any authenticated user, pass it to Component(_code=raw_code.code), and then call build_custom_component_template which compiles and executes the code on the server. Any authenticated user can thereby run arbitrary Python—reading secrets from the environment, accessing the database directly, or exfiltrating data—without any code sandboxing. This is a deliberate design feature of Langflow but represents a high-severity risk in multi-tenant or internet-facing deployments.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/endpoints.py:873` - resolves
  > `@router.post("/custom_component", status_code=HTTPStatus.OK)`
- `src/backend/base/langflow/api/v1/endpoints.py:878` - resolves
  > `component = Component(_code=raw_code.code)`
- `src/backend/base/langflow/api/v1/endpoints.py:880` - resolves
  > `built_frontend_node, component_instance = build_custom_component_template(component, user_id=user.id)`

---

## 8. IDOR: authenticated user can delete any message by UUID
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/monitor.py` (line 107)

delete_messages accepts a caller-supplied list of MessageTable UUIDs and issues a DELETE without checking that any of the targeted messages belong to a flow owned by the requesting user. An authenticated attacker who knows or enumerates message UUIDs can destroy another user's conversation history. No user-scoped subquery (such as the one used in get_messages at line 81) is applied here.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/monitor.py:104` - resolves
  > `@router.delete("/messages", status_code=204, dependencies=[Depends(get_current_active_user)])`
- `src/backend/base/langflow/api/v1/monitor.py:107` - resolves
  > `await session.exec(delete(MessageTable).where(MessageTable.id.in_(message_ids)))  # type: ignore[attr-defined]`

---

## 9. IDOR: authenticated user can overwrite any message record by UUID
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/monitor.py` (line 119)

update_message fetches a MessageTable row by the caller-supplied message_id UUID and updates its fields without checking that the message's flow_id belongs to a flow owned by the requesting user. Any authenticated user can tamper with another user's chat messages (e.g. alter text, mark as edited).

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/monitor.py:112` - resolves
  > `@router.put("/messages/{message_id}", dependencies=[Depends(get_current_active_user)], response_model=MessageRead)`
- `src/backend/base/langflow/api/v1/monitor.py:119` - resolves
  > `db_message = await session.get(MessageTable, message_id)`

---

## 10. IDOR: authenticated user can delete any session's messages by session_id
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/monitor.py` (line 183)

delete_messages_session deletes all MessageTable rows matching the caller-supplied session_id string without scoping the deletion to the requesting user's flows. An authenticated attacker can wipe another user's entire conversation session. The analogous get_messages endpoint correctly applies a user-scoped subquery (line 81) but this DELETE path omits it.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/monitor.py:176` - resolves
  > `@router.delete("/messages/session/{session_id}", status_code=204, dependencies=[Depends(get_current_active_user)])`
- `src/backend/base/langflow/api/v1/monitor.py:183` - resolves
  > `.where(col(MessageTable.session_id) == session_id)`

---

## 11. IDOR: authenticated user can reassign any session's messages to a new session_id
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/monitor.py` (line 151)

update_session_id fetches all MessageTable rows matching old_session_id and bulk-updates them to new_session_id without verifying the session belongs to a flow owned by the requesting user. An attacker can move another user's messages into their own session namespace or merge victim conversations.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/monitor.py:139` - resolves
  > `@router.patch(`
- `src/backend/base/langflow/api/v1/monitor.py:151` - resolves
  > `stmt = select(MessageTable).where(MessageTable.session_id == old_session_id)`

---

## 12. IDOR: authenticated user can read or delete vertex build data for any flow
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/monitor.py` (line 28)

get_vertex_builds and delete_vertex_builds both accept a caller-supplied flow_id query parameter and query the vertex_build table for that flow ID without verifying that the flow belongs to the requesting user. An authenticated attacker can enumerate build logs or wipe build state for any other user's flow by supplying its UUID.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/monitor.py:27` - resolves
  > `@router.get("/builds", dependencies=[Depends(get_current_active_user)])`
- `src/backend/base/langflow/api/v1/monitor.py:30` - resolves
  > `vertex_builds = await get_vertex_builds_by_flow_id(session, flow_id)`
- `src/backend/base/langflow/api/v1/monitor.py:36` - resolves
  > `@router.delete("/builds", status_code=204, dependencies=[Depends(get_current_active_user)])`

---

## 13. IDOR: authenticated user can read transaction history for any flow
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/monitor.py` (line 200)

get_transactions queries TransactionTable by the caller-supplied flow_id UUID without verifying that the flow belongs to the requesting user. An authenticated attacker can exfiltrate execution timestamps, input/output data, and error messages from another user's flows.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/monitor.py:193` - resolves
  > `@router.get("/transactions", dependencies=[Depends(get_current_active_user)])`
- `src/backend/base/langflow/api/v1/monitor.py:202` - resolves
  > `.where(TransactionTable.flow_id == flow_id)`

---

## 14. Global MCP tool/resource listing exposes all users' flows cross-tenant
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-285

- **Location:** `src/backend/base/langflow/api/v1/mcp_utils.py` (line 340)

When handle_list_tools and handle_list_resources are called without a project_id (i.e. from the global /mcp/sse and /mcp/streamable endpoints), the queries are select(Flow) with no user_id filter, returning flows from every user in the database. Any user authenticated to the global MCP endpoint can enumerate flow names, descriptions, and IDs belonging to all other tenants.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/mcp_utils.py:339` - resolves
  > `# Get all flows`
- `src/backend/base/langflow/api/v1/mcp_utils.py:340` - resolves
  > `flows_query = select(Flow)`
- `src/backend/base/langflow/api/v1/mcp_utils.py:104` - resolves
  > `flows_query = select(Flow).where(Flow.folder_id == project_id) if project_id else select(Flow)`

---

## 15. Unquoted filename in Content-Disposition header may allow header injection
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-113

- **Location:** `src/backend/base/langflow/api/v1/files.py` (line 129)

The Content-Disposition value is constructed with the file_name parameter unquoted (filename=<value>). RFC 6266 requires the value be a quoted-string or a token; without quotes, a filename containing semicolons or CRLF characters can inject additional header parameters or split the HTTP response header. The risk depends entirely on whether ValidatedFileName permits semicolons or CR/LF characters.

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/files.py:129` - resolves
  > `"Content-Disposition": f"attachment; filename={file_name} filename*=UTF-8''{file_name}",`

---
