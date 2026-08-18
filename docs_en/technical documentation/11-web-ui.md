# 11. Web interface

Classic server-side rendering with Go templates plus HTMX for partial updates. No SPA
framework and no build step - all static assets are embedded into the binary through
`go:embed`.

## Embedding assets

```go
//go:embed template
var templateFS embed.FS

//go:embed static
var staticFS embed.FS
```

The application ships as a single self-contained file with templates and static assets
inside. The flip side: changes in `template/` and `static/` require a rebuild, they
cannot be edited on a running server.

The engine is `github.com/gofiber/template/html/v2` on top of the standard library
`html/template`.

## Template layout

```
template/
├── main/           header, body, footer - the shared frame
├── navigation/     menus: authorized and public
├── login/          login form
├── overview/       dashboard summary
├── add_server/     servers
├── add_ssh/        SSH keys
├── add_certs/      issuing server certificates
├── revoke_certs/   revoking server certificates
├── add_entity/     entities for client certificates
├── add_oid/        custom OIDs
├── add_user_certs/ issuing client certificates
├── user_revoke_certs/  revoking client certificates
├── est/            EST: users and issuance
├── est_revoke_certs/   EST: revocation
├── ca/             Root, Sub and external CAs
├── ca_revoke_certs/    CA revocation
├── api_keys/       API keys
└── cert_info/      inspection of an uploaded certificate
```

Inside a section a single convention applies:

| File | Role |
|---|---|
| `<name>.html` | Full page: includes the header, menu, content and footer |
| `<name>-content.html` | Content for HTMX substitution without a page reload |
| `<name>List-tpl.html` | The list table, updated separately |
| `<name>List.html` | A wrapper around `-tpl` for rendering from a controller |

## Dual rendering

Every page controller distinguishes a normal navigation from an HTMX request:

```go
if c.Get("HX-Request") != "" {
    return c.Render("addESTCerts-content", data, "")   // content only
}
return c.Render("est/addESTCerts", data)               // the whole page
```

Thanks to this, menu navigation does not reload the page, while opening the URL directly
or pressing F5 still works.

## HTMX

The library is `static/js/htmx.min.js`. The main patterns:

```html
<!-- Menu navigation -->
<a hx-get="/add_est_certs" hx-target="#main-content" hx-swap="innerHTML" hx-push-url="true">

<!-- Submitting a form as JSON -->
<form hx-post="/add_est_certs" hx-ext="json-enc-custom" parse-types="true" hx-swap="none">

<!-- Deleting a table row -->
<button hx-post="/remove_est_cert" hx-target=".est_cert_id_5" hx-trigger="remove">
```

The `json-enc-custom` extension (`static/js/ext/`) encodes the form as JSON instead of
`application/x-www-form-urlencoded`, and `parse-types="true"` converts numeric fields
into numbers - otherwise `c.Bind().JSON()` on the Go side cannot map `"TTL": "365"` into
an `int`.

### The list update convention

Delete and revoke handlers return an **empty** list partial:

```go
return c.Render("est/estUserList-tpl", fiber.Map{})
```

This is done consistently across all sections. The reason: `hx-target` points at a
specific row (`.est_user_id_5`), and htmx replaces exactly that row. Returning the whole
table with data would nest it inside a `<tr>` and break the markup.

## Other scripts

| File | Purpose |
|---|---|
| `sweetalert2.all.min.js` | Confirmation dialogs - deletion and revocation require typing the object name |
| `table-sort.js` | Table sorting by clicking a header |
| `search-object.js` | Filtering lists and tables by substring |
| `keylength.js` | Switching the allowed key lengths when the algorithm changes |
| `drag-drop.js`, `ssh-upload.js`, `ext-ca-upload.js` | File upload by drag and drop |
| `menu-active.js` | Highlighting the active menu item |
| `api-key-show.js` | One-time display of a newly created API key |
| `addtag.js` | Entering SAN and OID values as tags |
| `bootstrap.bundle.js` | Collapsible menu blocks, dropdowns |

## Search

`search-object.js` works through event delegation: the listener sits on `document` and
inspects the `name` attribute of the input field. That matters for HTMX - tables are
recreated dynamically, and handlers bound directly to elements would be lost after every
swap.

The mapping between field name and search area is defined in a `switch`:

| Field `name` | What it filters |
|---|---|
| `search-server`, `search-entity`, `search-est-user` | Buttons in the left panel |
| `search-servers`, `search-est-users` | Table rows inside `.servers_table` |
| `search-certs`, `search-est-certs` | Rows of the certificate tables |

When adding a new section with search you have to set the `name` in the template **and**
add a branch to the `switch` - otherwise the field will be there but do nothing.

## Sessions

`middleware.InitSessionStore` configures the store:

| Parameter | Value | Meaning |
|---|---|---|
| `CookieSameSite` | `Lax` | Safari compatibility |
| `CookieSecure` | `app.protocol == "https"` | Follows the configuration automatically |
| `CookieHTTPOnly` | `true` | Not accessible from JavaScript |
| `IdleTimeout` | 30 minutes | Extended on activity |
| `CookieSessionOnly` | `false` | Survives closing the browser |

The store is in-memory, so **restarting the application logs everyone out**.

## Public pages

`/overview` and `/cert_info` are available without logging in and use
`menu-left-public-tpl.html`, a reduced menu. Controllers detect the state through
`middleware.IsAuthenticated(c)` and pick the matching template.

The **Certificate Info** section parses a certificate uploaded by the user: it shows the
Subject, issuer, serial number (in hex, as in the database), validity dates, SAN,
KeyUsage, CDP, AIA, and also the SKI and AKI - the last two are handy when debugging
chains and CRLs.
