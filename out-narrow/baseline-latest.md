# Agentic baseline - raw findings (no harness)

- **Run:** `base_e8a8362cc5b4`
- **Target:** `langflow` @ `1.7.3`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Files in scope:** 12  |  **Tokens:** 1441761  |  **Time:** 249.1s

> This is the output of the same model asked, in good faith, for the same rigor, but with nothing around it that enforces the rules. There is no evidence gate, no provenance, no bounded stop and no dedup between runs. Compare it with `findings/latest.md` from Foundry.

## Summary

| Verdict | Count |
|---|---|
| needs-review | 3 |
| true-positive | 7 |

## 1. Code injection via exec() with user-controlled vertex display_name
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94

- **Location:** `src/backend/base/langflow/helpers/flow.py` (line 327)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/helpers/flow.py:280` - resolves
  > `f"{input_.display_name.lower().replace(' ', '_')}: {INPUT_TYPE_MAP[input_.base_name]['type_hint']} = "`
- `src/backend/base/langflow/helpers/flow.py:293` - resolves
  > `arg_mappings = ", ".join(`
- `src/backend/base/langflow/helpers/flow.py:295` - resolves
  > `f'"{original_name}": {name}'`
- `src/backend/base/langflow/helpers/flow.py:327` - resolves
  > `exec(compiled_func, globals(), local_scope)  # noqa: S102`

---

## 2. Arbitrary server-side code execution via custom component endpoints
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` (line 878)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/endpoints.py:878` - resolves
  > `component = Component(_code=raw_code.code)`
- `src/backend/base/langflow/api/v1/endpoints.py:876` - resolves
  > `user: CurrentActiveUser,`
- `src/backend/base/langflow/api/v1/endpoints.py:911` - resolves
  > `component = Component(_code=code_request.code)`

---

## 3. IDOR: API key deletion without ownership check
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-639

- **Location:** `src/backend/base/langflow/api/v1/api_key.py` (line 50)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/api_key.py:44` - resolves
  > `@router.delete("/{api_key_id}", dependencies=[Depends(auth_utils.get_current_active_user)])`
- `src/backend/base/langflow/api/v1/api_key.py:45` - resolves
  > `async def delete_api_key_route(`
- `src/backend/base/langflow/api/v1/api_key.py:50` - resolves
  > `await delete_api_key(db, api_key_id)`

---

## 4. Unauthenticated access to the image download endpoint
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-306

- **Location:** `src/backend/base/langflow/api/v1/files.py` (line 139)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/files.py:138` - resolves
  > `@router.get("/images/{flow_id}/{file_name}")`
- `src/backend/base/langflow/api/v1/files.py:139` - resolves
  > `async def download_image(`
- `src/backend/base/langflow/api/v1/files.py:141` - resolves
  > `flow_id: UUID,`
- `src/backend/base/langflow/api/v1/files.py:107` - resolves
  > `async def download_file(`
- `src/backend/base/langflow/api/v1/files.py:109` - resolves
  > `flow: Annotated[Flow, Depends(get_flow)],`

---

## 5. Path traversal via unvalidated user-supplied filename in upload
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-22

- **Location:** `src/backend/base/langflow/api/v1/files.py` (line 97)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/files.py:97` - resolves
  > `file_name = file.filename or hashlib.sha256(file_content).hexdigest()`
- `src/backend/base/langflow/api/v1/files.py:98` - resolves
  > `full_file_name = f"{timestamp}_{file_name}"`
- `src/backend/base/langflow/api/v1/files.py:100` - resolves
  > `await storage_service.save_file(flow_id=folder, file_name=full_file_name, data=file_content)`

---

## 6. Authentication bypass when AUTO_LOGIN is enabled
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-287

- **Location:** `src/backend/base/langflow/api/v1/login.py` (line 91)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/login.py:88` - resolves
  > `@router.get("/auto_login")`
- `src/backend/base/langflow/api/v1/login.py:91` - resolves
  > `if auth_settings.AUTO_LOGIN:`
- `src/backend/base/langflow/api/v1/login.py:92` - resolves
  > `user_id, tokens = await create_user_longterm_token(db)`

---

## 7. Verbose internal exception detail leaked to API clients
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-209

- **Location:** `src/backend/base/langflow/api/v1/endpoints.py` (line 100)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/endpoints.py:100` - resolves
  > `raise HTTPException(status_code=500, detail=str(exc)) from exc`
- `src/backend/base/langflow/api/v1/chat.py:130` - resolves
  > `raise HTTPException(status_code=500, detail=str(exc)) from exc`
- `src/backend/base/langflow/api/v1/validate.py:23` - resolves
  > `raise HTTPException(status_code=500, detail=str(e)) from e`

---

## 8. HTTP response header injection via unquoted filename in Content-Disposition
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-113

- **Location:** `src/backend/base/langflow/api/v1/files.py` (line 129)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/files.py:129` - resolves
  > `"Content-Disposition": f"attachment; filename={file_name} filename*=UTF-8''{file_name}",`

---

## 9. Potential code execution inside validate_code on user-supplied source
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-94

- **Location:** `src/backend/base/langflow/api/v1/validate.py` (line 16)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/validate.py:3` - resolves
  > `from lfx.custom.validate import validate_code`
- `src/backend/base/langflow/api/v1/validate.py:16` - resolves
  > `errors = validate_code(code.code)`

---

## 10. Fallback returns raw store API key when decryption fails
**Verdict:** `needs-review`  |  **Severity:** `low`  |  **Class:** CWE-312

- **Location:** `src/backend/base/langflow/api/v1/store.py` (line 38)

**Evidence (citations), checked with the same resolver:**

- `src/backend/base/langflow/api/v1/store.py:37` - resolves
  > `except Exception:  # noqa: BLE001`
- `src/backend/base/langflow/api/v1/store.py:38` - resolves
  > `logger.exception("Failed to decrypt API key")`
- `src/backend/base/langflow/api/v1/store.py:39` - resolves
  > `return user.store_api_key`

---
