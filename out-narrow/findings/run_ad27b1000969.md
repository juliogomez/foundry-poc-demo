# Foundry PoC - security findings report

- **Run:** `run_ad27b1000969`
- **Target:** `langflow` @ `1.7.3`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 107  |  **Candidates:** 16  |  **Tokens:** 720830/1500000
- **Stop reason:** coverage-complete (all 107 units); trailing true-positive yield=0.25

## Summary

| Verdict | Count |
|---|---|
| true-positive | 3 |
| needs-review | 5 |
| false-positive | 8 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.

## 1. Authenticated user can execute arbitrary Python via custom component code  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` - `custom_component` (line 876)
- **Fingerprint:** `fp_eff3bce4a914ddcc`

Line 878 passes the raw caller-supplied code string directly into Component, and line 880 calls build_custom_component_template which compiles and executes that code. Although an authenticated user is required (line 876), any authenticated caller can supply a malicious Python string and achieve arbitrary server-side code execution, a full CWE-94 code injection.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/endpoints.py:876` - resolved
  > `user: CurrentActiveUser,`
- `src/backend/base/langflow/api/v1/endpoints.py:878` - resolved
  > `component = Component(_code=raw_code.code)`
- `src/backend/base/langflow/api/v1/endpoints.py:880` - resolved
  > `built_frontend_node, component_instance = build_custom_component_template(component, user_id=user.id)`

---

## 2. custom_component_update executes arbitrary caller-supplied Python code  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` - `custom_component_update` (line 898)
- **Fingerprint:** `fp_afb7d878ceab514b`

Line 911 passes caller-supplied code_request.code into Component without any sanitization, and line 912 hands it to build_custom_component_template which compiles and executes it. The authentication guard at line 898 does not prevent an authenticated attacker from achieving server-side arbitrary code execution.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/endpoints.py:898` - resolved
  > `user: CurrentActiveUser,`
- `src/backend/base/langflow/api/v1/endpoints.py:911` - resolved
  > `component = Component(_code=code_request.code)`
- `src/backend/base/langflow/api/v1/endpoints.py:912` - resolved
  > `component_node, cc_instance = build_custom_component_template(`

---

## 3. User-controlled display_name injected into exec'd function body  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `src/backend/base/langflow/helpers/flow.py` - `generate_function_for_flow` (line 280)
- **Fingerprint:** `fp_fbde3053ed1387d0`

Lines 280–281 embed input_.display_name directly into the generated Python source string with only `.lower().replace(' ', '_')` normalization, which does not neutralize special characters like `)`, `:`, or newlines. Line 327 calls exec() on the result. A flow definition whose vertex display_name contains injected Python syntax would execute arbitrary code on the server.

**Evidence (citations):**

- `src/backend/base/langflow/helpers/flow.py:280` - resolved
  > `f"{input_.display_name.lower().replace(' ', '_')}: {INPUT_TYPE_MAP[input_.base_name]['type_hint']} = "`
- `src/backend/base/langflow/helpers/flow.py:298` - resolved
  > `func_body = f"""`
- `src/backend/base/langflow/helpers/flow.py:327` - resolved
  > `exec(compiled_func, globals(), local_scope)  # noqa: S102`

---

## 4. create_upload_file has no visible authentication dependency  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` - `create_upload_file` (line 846)
- **Fingerprint:** `fp_aa1fe95787335300`

The function signature at lines 846–849 accepts only an UploadFile and a UUID with no CurrentActiveUser or API-key dependency. Without seeing the router decorator or a router-level auth middleware, it is not possible to confirm whether authentication is enforced before this handler executes.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/endpoints.py:846` - resolved
  > `async def create_upload_file(`
- `src/backend/base/langflow/api/v1/endpoints.py:847` - resolved
  > `file: UploadFile,`
- `src/backend/base/langflow/api/v1/endpoints.py:848` - resolved
  > `flow_id: UUID,`

---

## 5. auto_login issues long-term tokens to any unauthenticated caller when AUTO_LOGIN is enabled  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/login.py` - `auto_login` (line 91)
- **Fingerprint:** `fp_1895ac537897ffdb`

Line 91 checks only the application configuration flag AUTO_LOGIN; any unauthenticated HTTP client that reaches this endpoint when the flag is true will receive a valid long-lived access token and API key cookie at lines 93–117. Whether AUTO_LOGIN can be enabled in production deployments determines the real-world risk.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/login.py:91` - resolved
  > `if auth_settings.AUTO_LOGIN:`
- `src/backend/base/langflow/api/v1/login.py:92` - resolved
  > `user_id, tokens = await create_user_longterm_token(db)`
- `src/backend/base/langflow/api/v1/login.py:93` - resolved
  > `response.set_cookie(`

---

## 6. Webhook endpoint may bypass authentication depending on auth settings  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` - `webhook_run_flow` (line 612)
- **Fingerprint:** `fp_5e1278a4cf63b5d9`

The handler signature at lines 612–617 contains no standard authentication dependency such as CurrentActiveUser or an API-key guard; authentication is delegated entirely to the internal call at line 638. Whether that call enforces identity or allows anonymous execution depends on application configuration that is not visible in this unit.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/endpoints.py:612` - resolved
  > `async def webhook_run_flow(`
- `src/backend/base/langflow/api/v1/endpoints.py:638` - resolved
  > `webhook_user = await get_webhook_user(flow_id_or_name, request)`

---

## 7. Unsanitized caller filename embedded in storage path  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `src/backend/base/langflow/api/v1/files.py` - `upload_file` (line 97)
- **Fingerprint:** `fp_5bb1fcfc4ee3cea6`

Line 97 takes file.filename directly from the uploaded file object with no path-separator stripping, and line 98 prepends only a timestamp before producing full_file_name. Line 100 passes this string to storage_service.save_file. If the storage backend does not canonicalize the path, a filename containing '../' sequences could escape the intended folder.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/files.py:97` - resolved
  > `file_name = file.filename or hashlib.sha256(file_content).hexdigest()`
- `src/backend/base/langflow/api/v1/files.py:98` - resolved
  > `full_file_name = f"{timestamp}_{file_name}"`
- `src/backend/base/langflow/api/v1/files.py:100` - resolved
  > `await storage_service.save_file(flow_id=folder, file_name=full_file_name, data=file_content)`

---

## 8. download_image has no visible authentication dependency  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/files.py` - `download_image` (line 139)
- **Fingerprint:** `fp_c51d302382216e50`

The function signature at lines 139–142 accepts only ValidatedFileName and UUID with no CurrentActiveUser or API-key dependency. Without seeing the router-level decorator or middleware configuration, it cannot be confirmed that an unauthenticated caller is blocked from enumerating files across any flow.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/files.py:139` - resolved
  > `async def download_image(`
- `src/backend/base/langflow/api/v1/files.py:140` - resolved
  > `file_name: ValidatedFileName,`
- `src/backend/base/langflow/api/v1/files.py:141` - resolved
  > `flow_id: UUID,`

---

## 9. build_flow is protected by CurrentActiveUser dependency  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/chat.py` - `build_flow` (line 144)
- **Fingerprint:** `fp_dceae7a301002e21`

Line 144 declares `current_user: CurrentActiveUser` as a parameter, which FastAPI resolves as an authentication dependency before the handler body executes. The claim that resolution order matters is incorrect; FastAPI enforces all dependencies synchronously before calling the route handler. No authentication bypass exists in this code.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/chat.py:144` - resolved
  > `current_user: CurrentActiveUser,`

---

## 10. build_public_tmp intentionally serves unauthenticated public flows  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/chat.py` - `build_public_tmp` (line 597)
- **Fingerprint:** `fp_b4dd2972e12d6f10`

The endpoint is explicitly documented as being for flows that do not require authentication. Lines 630–631 enforce that only flows marked as public in the database can be executed, and the owner's permissions are used. Lack of an auth dependency is by design and is documented at lines 597–609.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/chat.py:597` - resolved
  > `"""Build a public flow without requiring authentication.`
- `src/backend/base/langflow/api/v1/chat.py:631` - resolved
  > `owner_user, new_flow_id = await verify_public_flow_and_get_user(flow_id=flow_id, client_id=client_id)`

---

## 11. Folder path derived from UUID is traversal-safe; filename handling is opaque  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` - `create_upload_file` (line 855)
- **Fingerprint:** `fp_4f09c614a3d1a55e`

The folder_name argument supplied to save_uploaded_file is constructed via `str(flow_id)` where flow_id is typed as UUID, making it a fixed-format safe string. The actual filename handling inside save_uploaded_file is not shown in this unit, so any traversal risk there cannot be attributed to code in lines 854–861.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/endpoints.py:855` - resolved
  > `flow_id_str = str(flow_id)`
- `src/backend/base/langflow/api/v1/endpoints.py:856` - resolved
  > `file_path = await asyncio.to_thread(save_uploaded_file, file, folder_name=flow_id_str)`

---

## 12. startswith prefix bypass is not reachable given prior allowlist controls  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `src/backend/base/langflow/api/v1/files.py` - `download_profile_picture` (line 188)
- **Fingerprint:** `fp_08691f94a5b71722`

The theoretical string-prefix bypass (e.g., /base/profile_pictures vs /base/profile_pictures_extra) cannot be constructed in practice because folder_name is validated against an explicit allowlist at line 188–189 and file_name is rejected if it contains any path separator at lines 192–193. These controls eliminate the inputs that would be required to reach an out-of-tree resolved path.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/files.py:188` - resolved
  > `if folder_name not in allowed_folders:`
- `src/backend/base/langflow/api/v1/files.py:192` - resolved
  > `if "/" in file_name or "\\" in file_name:`
- `src/backend/base/langflow/api/v1/files.py:205` - resolved
  > `if not str(file_path).startswith(str(allowed_base)):`

---

## 13. Refresh token in cookie is itself the credential; no missing auth  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/login.py` - `refresh_token` (line 141)
- **Fingerprint:** `fp_1de98f1333f02814`

Line 141 reads the refresh token from the cookie, and line 144 passes it to create_refresh_token which validates it before issuing new tokens. The token is the authentication credential; a handler that consumes and validates it does not need an additional auth dependency. This is standard token-refresh design.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/login.py:141` - resolved
  > `token = request.cookies.get("refresh_token_lf")`
- `src/backend/base/langflow/api/v1/login.py:144` - resolved
  > `tokens = await create_refresh_token(token, db)`

---

## 14. Unauthenticated logout has no exploitable impact  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `src/backend/base/langflow/api/v1/login.py` - `logout` (line 172)
- **Fingerprint:** `fp_937f39beeca4c51d`

The logout handler at line 172 only deletes cookies in the HTTP response at lines 175–195. An unauthenticated caller issuing this request has no session to invalidate and receives no sensitive data. The absence of an auth guard is a minor design concern but not an exploitable vulnerability.

**Evidence (citations):**

- `src/backend/base/langflow/api/v1/login.py:172` - resolved
  > `async def logout(response: Response):`
- `src/backend/base/langflow/api/v1/login.py:175` - resolved
  > `response.delete_cookie(`
- `src/backend/base/langflow/api/v1/login.py:196` - resolved
  > `return {"message": "Logout successful"}`

---

## 15. ORM getattr column selection is not SQL injection  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-89  |  **Rule:** `EXPLORATORY`

- **Location:** `src/backend/base/langflow/helpers/flow.py` - `list_flows_by_flow_folder` (line 81)
- **Fingerprint:** `fp_81166939099c5454`

Line 81 uses Python's built-in getattr against the SQLModel Flow class with a safe default fallback (Flow.updated_at), so an unknown column name simply returns the default attribute rather than injecting raw SQL. Line 82 dispatches direction through SORT_DISPATCHER, not by concatenation into a query string. Neither pattern constitutes CWE-89.

**Evidence (citations):**

- `src/backend/base/langflow/helpers/flow.py:81` - resolved
  > `sort_col = getattr(Flow, order_params.get("column", "updated_at"), Flow.updated_at)`
- `src/backend/base/langflow/helpers/flow.py:82` - resolved
  > `sort_dir = SORT_DISPATCHER.get(order_params.get("direction", "desc"), desc)`

---

## 16. ORM getattr column selection is not SQL injection  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-89  |  **Rule:** `EXPLORATORY`

- **Location:** `src/backend/base/langflow/helpers/flow.py` - `list_flows_by_folder_id` (line 115)
- **Fingerprint:** `fp_ff07e2de34e22bfd`

Line 115 mirrors the same pattern as unit 13: getattr resolves a Python attribute on the Flow ORM model with a safe default, never concatenating user input into raw SQL. Line 116 uses SORT_DISPATCHER for safe direction resolution. No SQL injection vector exists here.

**Evidence (citations):**

- `src/backend/base/langflow/helpers/flow.py:115` - resolved
  > `sort_col = getattr(Flow, order_params.get("column", "updated_at"), Flow.updated_at)`
- `src/backend/base/langflow/helpers/flow.py:116` - resolved
  > `sort_dir = SORT_DISPATCHER.get(order_params.get("direction", "desc"), desc)`

---
