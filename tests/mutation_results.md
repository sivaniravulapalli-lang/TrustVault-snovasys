## Tests

Run: `pytest -q` (82 tests, all passing). CI runs the same on every push (`.github/workflows/tests.yml`).

### Mutation checks

To prove the tests actually detect broken security rules, I temporarily broke
the code in 12 ways, ran the suite, and reverted each change with
`git checkout`. Every mutation is caught by at least one test.

| # | Threat | Temporary change | Failing tests |
|---|--------|------------------|---------------|
| 1 | Stranger reads a document | `view`: authz check removed | 7 |
| 2 | Stranger reads a document by id | `get_one`: authz check removed | 7 |
| 3 | Stranger / read-only user edits metadata | `edit_meta`: authz check removed | 9 |
| 4 | Stranger / read-only user replaces content | `replace_content`: authz check removed | 7 |
| 5 | Non-owner deletes a document | `delete`: authz check removed | 10 |
| 6 | Stranger manages shares | `shares.py` endpoint: authz check removed | 35 |
| 7 | Search/list leaks other users' documents | `visible()` returns everything | 5 |
| 8 | Deleted document still accessible | `deleted_at` check removed | 2 |
| 9 | Admin gains access to documents | admin branch returns `action == "delete"` | 1 |
| 10 | Unknown/new action allowed by accident | `KNOWN_ACTIONS` deny-by-default removed | 1 (new test added after first run showed 0) |
| 11 | Expired token accepted | `verify_exp` disabled | 1 |
| 12 | New users get excessive role | `register` assigns `Role.owner` | 2 |

Finding: mutation #10 initially failed 0 tests, revealing a gap. I added
`test_unknown_action_is_denied_even_for_owner`, and the mutation is now caught.