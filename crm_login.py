"""CRM OAuth login form HTML."""

from __future__ import annotations

import html


def render_login_page(
    *,
    txn_id: str,
    form_action: str = "/crm-auth/login",
    error_message: str | None = None,
) -> str:
    error_block = ""
    if error_message:
        error_block = f"""
        <div class="error" role="alert">{html.escape(error_message)}</div>
        """

    txn_escaped = html.escape(txn_id)
    action_escaped = html.escape(form_action)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Connect Your CRM Account</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #f6f7f9; margin: 0; padding: 2rem; }}
    .card {{ max-width: 420px; margin: 0 auto; background: #fff; padding: 2rem; border-radius: 12px;
              box-shadow: 0 8px 24px rgba(0,0,0,.08); }}
    h1 {{ font-size: 1.35rem; margin-top: 0; }}
    label {{ display: block; font-weight: 600; margin: 1rem 0 .35rem; }}
    input {{ width: 100%; padding: .65rem .75rem; border: 1px solid #ccd2da; border-radius: 8px; box-sizing: border-box; }}
    button {{ margin-top: 1.25rem; width: 100%; padding: .75rem; border: 0; border-radius: 8px;
               background: #0b5fff; color: #fff; font-weight: 600; cursor: pointer; }}
    .error {{ background: #fdecec; color: #8a1f1f; padding: .75rem; border-radius: 8px; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Connect Your CRM Account</h1>
    {error_block}
    <form method="post" action="{action_escaped}" autocomplete="off">
      <input type="hidden" name="txn_id" value="{txn_escaped}" />
      <label for="company_id">Company ID</label>
      <input id="company_id" name="company_id" required autocomplete="off" />
      <label for="crm_api_token">CRM API Token</label>
      <input id="crm_api_token" name="crm_api_token" type="password" required autocomplete="off" />
      <button type="submit">Connect CRM</button>
    </form>
  </div>
</body>
</html>"""
