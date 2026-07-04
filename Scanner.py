#!/usr/bin/env python3
# =============================================================================
#  TECH-INTELLIGENCE v1.0
#  Advanced HTTP Parameter Discovery & Fuzzing Engine
#  Author: HackerAI / Tech-Intelligence
#  Purpose: Authorized penetration testing — parameter enumeration
# =============================================================================

import os
import sys
import time
import socket
import ssl
import urllib.parse
import json
from datetime import datetime
from typing import List, Tuple, Optional

# ──────────────────────────────────────────────────────────────────────────────
#  BANNER
# ──────────────────────────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     ████████╗███████╗ ██████╗██╗  ██╗    ██╗███╗   ██╗████████╗             ║
║     ╚══██╔══╝██╔════╝██╔════╝██║  ██║    ██║████╗  ██║╚══██╔══╝             ║
║        ██║   █████╗  ██║     ███████║    ██║██╔██╗ ██║   ██║                ║
║        ██║   ██╔══╝  ██║     ██╔══██║    ██║██║╚██╗██║   ██║                ║
║        ██║   ███████╗╚██████╗██║  ██║    ██║██║ ╚████║   ██║                ║
║        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝    ╚═╝╚═╝  ╚═══╝   ╚═╝                ║
║                                                                              ║
║     ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗███████╗████████╗███████╗██╗ ║
║     ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝╚══██╔══╝██╔════╝██║ ║
║     ██████╔╝███████║██████╔╝███████║██╔████╔██║███████╗   ██║   █████╗  ██║ ║
║     ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║╚════██║   ██║   ██╔══╝  ╚═╝ ║
║     ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████║   ██║   ███████╗██╗ ║
║     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝ ║
║                                                                              ║
║               ██████╗ ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗  ║
║               ██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗ ║
║               ██║  ██║██║███████╗██║     ██║   ██║██║   ██║█████╗  ██████╔╝ ║
║               ██║  ██║██║╚════██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗ ║
║               ██████╔╝██║███████║╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║ ║
║               ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ║
║                                                                              ║
║           HTTP PARAMETER DISCOVERY & FUZZING ENGINE v1.0                     ║
║                                                                              ║
║  [!] AUTHORIZED USE ONLY                                                     ║
║  I have permission and am authorized to perform this penetration test        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ──────────────────────────────────────────────────────────────────────────────
#  COLORS
# ──────────────────────────────────────────────────────────────────────────────

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    DIM = '\033[2m'

    @staticmethod
    def colorize(text, color):
        return f"{color}{text}{Colors.RESET}"

# ──────────────────────────────────────────────────────────────────────────────
#  POWERFUL DEFAULT WORDLIST (2,500+ parameters)
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_PARAM_WORDLIST = [
    # === AUTH & SESSION ===
    "id", "user", "username", "user_id", "uid", "userid", "account", "account_id",
    "login", "password", "pass", "pwd", "passwd", "token", "access_token",
    "refresh_token", "auth", "auth_token", "session", "session_id", "sid",
    "api_key", "apikey", "key", "secret", "secret_key", "private_key",
    "public_key", "jwt", "bearer", "authorization", "auth_type",
    "login_token", "csrf", "csrf_token", "nonce", "xsrf", "xsrf_token",
    "captcha", "recaptcha", "g-recaptcha-response", "h-captcha-response",
    "otp", "mfa", "2fa", "two_factor", "verification_code", "verify_token",
    "reset_token", "remember_me", "remember", "stay_logged_in",
    "logout", "signout", "signout_token", "deauth",

    # === ADMIN / PRIVILEGE ===
    "admin", "adm", "is_admin", "role", "roles", "permission", "permissions",
    "priv", "privilege", "privileges", "access", "access_level", "level",
    "user_type", "usertype", "is_admin", "is_mod", "mod", "superadmin",
    "root", "sudo", "debug", "dbg", "test", "testing", "env", "environment",
    "config", "configuration", "settings", "setup", "install", "bypass",
    "bypass_auth", "bypassauth", "override", "is_admin", "isAdmin",
    "admin_token", "godmode", "god_mode", "dev", "developer", "dev_mode",
    "maintenance", "maintenance_mode", "bypass_captcha",
    "grant", "revoke", "elevate", "impersonate", "masquerade",
    "switch_user", "_switch_user", "su", "sudo",

    # === PAGINATION & LISTING ===
    "page", "page_id", "p", "page_number", "page_num", "num", "count",
    "limit", "offset", "start", "end", "from", "to", "skip", "take",
    "per_page", "perpage", "max", "min", "size", "pagesize", "page_size",
    "total", "records", "record_count", "show", "display", "display_length",
    "length", "index", "idx", "current_page", "next_page", "prev_page",
    "first", "last", "batch", "batch_size", "chunk", "chunks",
    "pagination", "paginate", "pageIndex", "pageSize",
    "iDisplayStart", "iDisplayLength", "draw",
    "order", "order_by", "orderby", "sort", "sort_by", "sortby",
    "sort_order", "sortorder", "direction", "dir", "asc", "desc",
    "sort_by", "sort_field", "sortfield",

    # === SEARCH & FILTER ===
    "q", "query", "search", "search_query", "keyword", "keywords",
    "filter", "filters", "filter_by", "find", "lookup", "term", "terms",
    "tag", "tags", "category", "cat", "categories", "section",
    "type", "types", "status", "state", "condition", "where",
    "match", "like", "contains", "begins_with", "ends_with",
    "regex", "pattern", "wildcard", "glob",
    "select", "selected", "option", "options",
    "include", "includes", "exclude", "excludes",
    "only", "except", "having", "group", "group_by",

    # === CRUD OPERATIONS ===
    "action", "act", "do", "op", "operation", "method", "cmd", "command",
    "exec", "execute", "run", "process", "perform",
    "create", "add", "new", "insert", "store",
    "read", "get", "fetch", "load", "retrieve",
    "update", "edit", "modify", "change", "save",
    "delete", "remove", "destroy", "erase", "purge", "trash",
    "submit", "send", "post", "put", "patch",
    "upload", "download", "import", "export",
    "clone", "copy", "duplicate", "move", "rename",
    "enable", "disable", "activate", "deactivate",
    "approve", "reject", "publish", "unpublish",
    "archive", "unarchive", "restore", "recover",
    "lock", "unlock", "block", "unblock", "ban", "unban",
    "suspend", "unsuspend", "cancel", "undo",
    "validate", "verify", "confirm", "check",

    # === FILE & PATH ===
    "file", "filename", "file_name", "filepath", "file_path", "path",
    "dir", "directory", "folder", "document", "doc", "pdf", "docx",
    "image", "img", "photo", "picture", "pic", "avatar",
    "attachment", "attach", "upload", "download", "dl",
    "url", "uri", "link", "href", "src", "source",
    "target", "dest", "destination", "redirect", "redir",
    "return", "return_url", "return_to", "next", "go",
    "callback", "cb", "webhook", "hook",
    "endpoint", "api", "api_url", "base_url", "base_path",
    "template", "tpl", "view", "render", "partial",
    "include", "require", "import_file",
    "ext", "extension", "format", "output_format",

    # === IDENTIFIERS ===
    "id", "ID", "Id", "iid", "uid", "uuid", "guid",
    "ref", "reference", "code", "code_id", "sku",
    "pid", "product_id", "productid", "item_id",
    "oid", "order_id", "orderid", "invoice_id",
    "cid", "customer_id", "client_id", "member_id",
    "tid", "transaction_id", "payment_id",
    "sid", "store_id", "shop_id", "site_id",
    "gid", "group_id", "team_id", "org_id",
    "rid", "role_id", "resource_id",
    "eid", "event_id", "ticket_id",
    "lid", "location_id", "address_id",
    "mid", "message_id", "thread_id",
    "fid", "folder_id", "file_id",
    "bid", "blog_id", "post_id", "article_id",
    "uid", "user_id", "account_id", "profile_id",
    "nid", "node_id", "entity_id",
    "hash", "hash_id", "slug",

    # === USER INFO ===
    "name", "fullname", "firstname", "lastname", "fname", "lname",
    "email", "mail", "e-mail", "email_address",
    "phone", "phone_number", "mobile", "tel", "telephone",
    "address", "city", "state", "zip", "zipcode", "country",
    "dob", "birthdate", "birthday", "age",
    "gender", "sex", "title", "prefix",
    "company", "organization", "org",
    "website", "url", "bio", "about",
    "ip", "ip_address", "user_agent", "ua", "browser",
    "lang", "language", "locale", "timezone", "tz",
    "avatar", "profile_pic", "profile_picture",
    "social", "facebook", "twitter", "instagram", "linkedin",
    "nickname", "display_name", "handle", "signature",
    "description", "desc", "note", "notes", "comment",

    # === SECURITY & DEBUG ===
    "debug", "dbg", "debug_mode", "_debug", "trace",
    "verbose", "v", "vv", "vvv", "log", "logs",
    "logging", "loglevel", "log_level", "verbosity",
    "profiling", "profile", "benchmark", "timer",
    "error", "errors", "error_log", "exception",
    "stacktrace", "stack_trace", "backtrace",
    "dump", "var_dump", "print_r",
    "phpinfo", "info", "server_info",
    "health", "healthcheck", "ping", "pong",
    "status", "system", "sysinfo",
    "diag", "diagnostic", "diagnostics",
    "metrics", "prometheus", "grafana",
    "test", "mock", "stub", "sandbox",
    "bypass", "override", "force",
    "inspect", "inspectlet",
    "_method", "X-HTTP-Method-Override", "x-http-method-override",
    "__proto__", "constructor", "prototype",

    # === SQL INJECTION VECTORS ===
    "db", "database", "dbs", "db_name", "dbname", "table", "tables",
    "column", "columns", "field", "fields", "row", "rows",
    "sql", "query", "raw", "native_query",
    "where", "having", "group_concat",
    "union", "select", "from", "into",
    "order", "order_by", "group_by",
    "like", "between", "in", "not_in",
    "null", "is_null", "count", "avg", "sum", "min", "max",

    # === COMMAND INJECTION ===
    "cmd", "command", "exec", "execute", "run",
    "system", "shell", "bash", "sh", "powershell",
    "ping", "traceroute", "nslookup", "dig", "host",
    "whoami", "id", "uname", "hostname",
    "ls", "dir", "cat", "type", "more", "less",
    "wget", "curl", "fetch", "nc", "netcat",
    "python", "perl", "ruby", "php", "node",
    "eval", "exec_command", "system_command",

    # === SSRF / LFI / RFI ===
    "url", "uri", "link", "href", "src", "href",
    "file", "document", "page", "load",
    "include", "require", "require_once", "include_once",
    "path", "root", "base", "base_path",
    "template", "view", "render",
    "fetch", "read_file", "readfile",
    "proxy", "proxies", "proxy_url",
    "dest", "destination", "redirect_url",
    "import", "export_url",
    "img", "image_url", "photo_url",
    "css", "style", "script", "js",
    "data", "remote", "external",
    "server", "server_name", "server_addr",
    "host", "hostname", "port",
    "internal", "local", "localhost",
    "backend", "backends",
    "api_url", "api_endpoint",
    "callback_url", "notify_url", "webhook_url",
    "return_url", "cancel_url", "error_url",
    "success_url", "failure_url",
    "redirect_uri", "redirect_url",
    "forward", "forwarded",

    # === API / REST ===
    "api", "apiversion", "api_version", "v", "version",
    "format", "fmt", "response_format", "output",
    "pretty", "prettyprint", "callback",
    "fields", "select", "expand", "embed",
    "include", "exclude", "with",
    "sort", "order", "order_by",
    "page", "per_page", "limit", "offset",
    "filter", "filters", "q", "query",
    "lang", "language", "locale",
    "timestamp", "ts", "_t",
    "signature", "sig", "hash",
    "app_id", "client_id", "client_secret",
    "grant_type", "scope", "state",
    "response_type", "redirect_uri",
    "code", "authorization_code",
    "access_token", "refresh_token",
    "id_token", "token_type", "expires_in",
    "nonce", "prompt", "acr_values",
    "login_hint", "domain_hint",
    "resource", "audience",
    "meta", "metadata",
    "prettyPrint", "alt", "fields",
    "key", "apiKey", "api_key",
    "oauth_token", "oauth_verifier", "oauth_nonce",
    "oauth_timestamp", "oauth_signature", "oauth_signature_method",
    "oauth_consumer_key", "oauth_callback",
    "bearer", "Authorization",

    # === PAYMENT ===
    "price", "amount", "total", "subtotal", "discount",
    "tax", "vat", "shipping", "handling",
    "currency", "currency_code", "ccy",
    "payment_method", "payment_type", "pay_type",
    "card", "card_number", "cc", "cc_number",
    "cvv", "cvc", "expiry", "expiration", "expiry_date",
    "cardholder", "cardholder_name",
    "billing", "billing_address",
    "shipping_address",
    "order_id", "transaction_id", "invoice",
    "payment_id", "charge_id",
    "subscription", "sub_id",
    "plan", "plan_id", "tier",
    "coupon", "promo", "promo_code", "gift_card",
    "quantity", "qty", "item_count",
    "checkout", "checkout_id",
    "success_url", "cancel_url", "return_url",

    # === CONFIG / SETTINGS ===
    "config", "conf", "cfg", "configuration",
    "settings", "setting", "prefs", "preferences",
    "options", "option", "params", "parameters",
    "setup", "install", "init",
    "mode", "environment", "env",
    "theme", "template", "skin",
    "layout", "style", "css_class",
    "color", "font", "font_size",
    "timeout", "ttl", "cache", "cache_ttl",
    "retry", "retries", "max_retries",
    "max_size", "max_length", "max_file_size",
    "min_length", "min_size",
    "allowed_types", "allowed_extensions",
    "feature", "features", "flags",
    "beta", "experimental",
    "readonly", "read_only", "readonly_mode",
    "wysiwyg", "editor", "rich_edit",
    "autocomplete", "autofill",
    "validation", "validate",
    "sanitize", "sanitize_input",
    "escape", "encode", "decode",
    "charset", "encoding",

    # === LOGGING & MONITORING ===
    "log", "logs", "logging", "logfile", "log_file",
    "log_level", "loglevel", "lvl",
    "error_log", "access_log", "audit_log",
    "monitor", "monitoring", "watch",
    "alert", "alerts", "notification", "notifications",
    "webhook", "webhooks", "callback_url",
    "slack", "slack_webhook", "discord",
    "email_notify", "email_alert",
    "sms", "sms_alert",
    "metrics", "stats", "statistics",
    "grafana", "prometheus", "datadog",
    "newrelic", "sentry",
    "trace", "tracing", "span",
    "request_id", "correlation_id",
    "user_agent", "referer", "referrer",
    "origin", "source_ip",
    "timestamp", "datetime", "date",

    # === TIME & DATE ===
    "date", "datetime", "time", "timestamp", "ts",
    "from_date", "to_date", "start_date", "end_date",
    "from_time", "to_time", "start_time", "end_time",
    "year", "month", "day", "hour", "minute", "second",
    "week", "weekday", "week_number",
    "range", "date_range", "time_range",
    "period", "interval", "duration",
    "schedule", "scheduled_at",
    "created_at", "updated_at", "deleted_at",
    "created", "updated", "modified",
    "expires", "expires_at", "expiry",
    "since", "until", "before", "after",

    # === LOCALIZATION ===
    "lang", "language", "locale", "locale_code",
    "country", "country_code", "region",
    "timezone", "tz", "utc_offset",
    "currency", "currency_code",
    "date_format", "time_format", "number_format",
    "unit_system", "units", "measurement",
    "translation", "translate", "i18n", "l10n",

    # === MESSAGING ===
    "message", "msg", "text", "body", "content",
    "subject", "title", "heading",
    "sender", "recipient", "to", "cc", "bcc",
    "reply_to", "in_reply_to",
    "thread", "thread_id", "conversation",
    "channel", "channel_id", "room",
    "notification", "push", "push_token",
    "template_id", "email_template",
    "priority", "urgent", "important",

    # === SOCIAL / SHARING ===
    "share", "share_url", "share_text",
    "like", "dislike", "rating", "review",
    "follow", "unfollow", "subscribe", "unsubscribe",
    "friend", "friend_id", "invite",
    "comment", "reply", "post",
    "tweet", "retweet", "favorite",
    "view_count", "views",

    # === CLOUD & INFRASTRUCTURE ===
    "region", "zone", "availability_zone",
    "instance", "instance_id", "instance_type",
    "cluster", "cluster_id", "node",
    "container", "container_id", "pod",
    "namespace", "service", "service_name",
    "bucket", "bucket_name", "object_key",
    "queue", "queue_name", "topic",
    "function", "function_name", "arn",
    "stack", "stack_id", "stack_name",
    "secret_name", "secret_arn",
    "kms", "kms_key",
    "iam", "role_arn", "policy",
    "vpc", "subnet", "security_group",

    # === OAUTH / SSO ===
    "client_id", "client_secret",
    "redirect_uri", "redirect_url",
    "response_type", "grant_type",
    "code", "authorization_code",
    "state", "scope", "audience",
    "login_hint", "domain_hint",
    "acr_values", "claims",
    "id_token_hint", "prompt",
    "max_age", "ui_locales",
    "resource", "access_type",
    "approval_prompt", "include_granted_scopes",
    "request", "request_uri",
    "registration", "post_logout_redirect_uri",

    # === WORDPRESS SPECIFIC ===
    "s", "p", "page_id", "post_id", "cat", "tag",
    "author", "m", "year", "monthnum", "day",
    "w", "hour", "minute", "second",
    "post_type", "post_status", "posts_per_page",
    "wpnonce", "_wpnonce", "_wp_http_referer",
    "action", "doing_wp_cron",
    "rest_route", "rest_route",
    "wp_rest", "rest",
    "option", "options",
    "meta", "meta_key", "meta_value",
    "shortcode", "shortcodes",
    "elementor", "fl_builder",
    "wc-ajax", "wcapi",
    "wc_nonce",
    "page_id", "category_id", "tag_id",
    "preview", "view",
    "format", "embed",
    "amp", "amp",

    # === DRUPAL SPECIFIC ===
    "q", "drupal", "destination",
    "element", "elements",
    "form_id", "form_build_id",
    "op", "submit",
    "render", "rendered",
    "field", "fields",
    "node", "nid",
    "term", "tid",
    "user", "uid",
    "profile", "profile_id",
    "comment", "cid",
    "view_name", "display_id",
    "arg", "args",
    "page", "page_number",
    "sort", "order",
    "search", "keys",
    "filter", "f",

    # === JOOMLA SPECIFIC ===
    "option", "view", "task", "layout",
    "format", "id", "catid",
    "Itemid", "controller",
    "tmpl", "template",
    "lang", "language",
    "group", "limit", "limitstart",
    "search", "filter",
    "start", "list",
    "type", "types",
    "user_id", "group_id",
    "return", "url",
    "base", "basedir",
    "com_", "component",
    "module", "modules",

    # === MAGENTO SPECIFIC ===
    "___store", "___from_store",
    "SID", "form_key",
    "isAjax", "ajax",
    "qty", "product",
    "price", "super_attribute",
    "options", "bundle_option",
    "token", "oauth_token",
    "limit", "order", "dir",
    "filter", "search",
    "page", "limit_page",
    "type_id", "store_id",

    # === LARAVEL SPECIFIC ===
    "_token", "_method",
    "redirect", "intended",
    "session", "remember",
    "page", "search",
    "filter", "order",
    "sort", "direction",
    "with", "withCount",
    "where", "orWhere",
    "find", "first",
    "paginate", "simplePaginate",
    "api_token",
    "XDEBUG_SESSION",
    "PHP_IDE_CONFIG",
    "debugbar", "_debugbar",

    # === NODE.JS / EXPRESS ===
    "__proto__", "constructor", "prototype",
    "length", "toString",
    "_csrf", "csrf_token",
    "session", "connect.sid",
    "callback", "cb",
    "jsonp", "jsonpcallback",
    "format", "ext",
    "next", "redirect",
    "partials", "views",
    "locals", "app.locals",
    "env", "NODE_ENV",
    "PORT", "port",
    "HOST", "host",

    # === JAVA / SPRING ===
    "spring", "actuator",
    "env", "health",
    "beans", "mappings",
    "trace", "dump",
    "loggers", "metrics",
    "heapdump", "threaddump",
    "configprops", "auditevents",
    "caches", "conditions",
    "flyway", "liquibase",
    "httptrace", "scheduledtasks",
    "sessions", "shutdown",
    "jolokia", "logfile",
    "prometheus", "info",
    "refresh", "restart",
    "management", "actuator",
    "_method", "X-HTTP-Method-Override",
    "filter", "DNT",
    "X-Forwarded-For", "X-Forwarded-Host",
    "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Real-IP", "X-Original-URL",
    "X-Rewrite-URL", "X-Custom-IP-Authorization",

    # === ASP.NET SPECIFIC ===
    "__VIEWSTATE", "__EVENTVALIDATION",
    "__EVENTTARGET", "__EVENTARGUMENT",
    "__LASTFOCUS", "__CALLBACKID",
    "__CALLBACKPARAM",
    "ctl00", "ctl01",
    "ScriptManager", "ScriptManager1",
    "UpdatePanel", "UpdatePanel1",
    "ASPSESSIONID", "ASP.NET_SessionId",
    ".ASPXAUTH", "X-Requested-With",

    # === API GATEWAY / PROXY ===
    "X-Forwarded-For", "X-Forwarded-Host",
    "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Real-IP", "X-Original-URL",
    "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Client-IP",
    "X-Host", "Forwarded",
    "Via", "X-Cache",
    "X-Cache-Hits", "CF-Connecting-IP",
    "True-Client-IP",
    "X-HTTP-Method", "X-HTTP-Method-Override",
    "X-Method-Override", "X-HTTP-Method",
    "Access-Control-Allow-Origin",
    "Origin", "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
    "X-Requested-With",
    "X-Content-Type-Options",
    "X-Frame-Options", "X-XSS-Protection",
    "Content-Security-Policy", "Referrer-Policy",

    # === CLOUDFLARE ===
    "CF-IPCountry", "CF-Ray",
    "CF-Visitor", "CF-Connecting-IP",
    "CF-Request-ID", "__cfduid",
    "cf_clearance",

    # === CACHING ===
    "cache", "nocache", "no-cache",
    "cachebuster", "cb", "_",
    "fresh", "refresh",
    "purge", "bust",
    "version", "v",

    # === ANALYTICS ===
    "utm_source", "utm_medium", "utm_campaign",
    "utm_term", "utm_content",
    "utm_id", "utm_cid",
    "gclid", "fbclid",
    "msclkid", "dclid",
    "gbraid", "wbraid",
    "_ga", "_gid", "_gat",
    "ref", "referral",
    "source", "medium",
    "campaign", "content",
    "gad_source", "gad_campaign",
    "yclid", "igshid",
    "mc_cid", "mc_eid",
    "trk", "trkCampaign",
    "pk_source", "pk_medium", "pk_campaign",
    "pk_keyword", "pk_content",
    "mtm_source", "mtm_medium", "mtm_campaign",
    "mtm_keyword", "mtm_content",

    # === CORS ===
    "origin", "Origin",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Request-Method",
    "Access-Control-Request-Headers",

    # === WEBDAV ===
    "PROPFIND", "PROPPATCH", "MKCOL",
    "COPY", "MOVE", "LOCK", "UNLOCK",
    "depth", "Destination",
    "If", "Lock-Token",
    "Overwrite", "Timeout",

    # === GRAPHQL ===
    "query", "mutation", "subscription",
    "variables", "operationName",
    "extensions", "persistedQuery",
    "sha256Hash", "version",
    "graphql", "gql",
    "introspection", "__typename",
    "id", "node",
    "first", "last",
    "after", "before",

    # === JSON API ===
    "data", "attributes",
    "relationships",
    "included", "meta",
    "jsonapi", "json",

    # === RPC ===
    "method", "params",
    "jsonrpc", "xmlrpc",
    "soap", "wsdl",

    # === COMMON PARAM NAMES (short) ===
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "aa", "bb", "cc", "dd", "ee",
    "id", "ID", "Id",
    "ok", "no", "go", "do",
    "up", "in", "on", "at", "by", "to",
    "is", "it", "be", "as",
    "x", "y", "z",

    # === OTHERS ===
    "data", "info", "result", "results",
    "response", "output", "out",
    "input", "inp", "value", "val",
    "code", "codes",
    "list", "listing",
    "item", "items",
    "detail", "details",
    "summary", "overview",
    "report", "reports",
    "analytics", "insights",
    "export", "import",
    "generate", "preview",
    "validate", "verify",
    "resolve", "lookup",
    "track", "tracking",
    "flag", "flags",
    "mode", "modes",
    "type", "types",
    "class", "classes",
    "style", "styles",
    "color", "colors",
    "icon", "icons",
    "image", "images",
    "media", "video", "audio",
    "font", "fonts",
    "size", "sizes",
    "dimension", "dimensions",
    "width", "height", "depth",
    "coord", "coordinates",
    "position", "coordinates",
    "latitude", "lat", "longitude", "lng", "lon",
    "address", "location",
    "distance", "radius",
    "unit", "units",
    "speed", "velocity",
    "weight", "mass",
    "temp", "temperature",
    "voltage", "current",
    "power", "energy",
    "pressure", "humidity",
    "altitude", "elevation",
    "heading", "bearing",
    "accuracy", "precision",
    "signal", "strength",
    "battery", "charge",
    "network", "wifi", "bluetooth",
    "device", "device_id", "device_type",
    "platform", "os", "os_version",
    "app", "app_id", "app_version",
    "build", "build_number",
    "release", "release_version",
    "channel", "distribution",
    "provider", "vendor",
    "partner", "affiliate",
    "campaign", "promotion",
    "source", "medium",
    "ad", "ad_id", "ad_group",
    "creative", "banner",
    "impression", "click",
    "conversion", "funnel",
    "retarget", "remarketing",
    "segment", "cohort",
    "variation", "experiment",
    "a_b", "ab_test",
    "personalized", "recommendation",
    "score", "rank", "rating",
    "votes", "popularity",
    "trending", "featured",
    "sponsored", "promoted",
    "highlight", "spotlight",
    "random", "shuffle",
    "related", "similar",
    "suggested", "recommended",
    "recent", "latest", "new",
    "popular", "top", "best",
    "hot", "trending",
    "random", "any",
    "sample", "example",
    "demo", "trial",
    "free", "premium", "pro",
    "basic", "advanced",
    "simple", "detailed",
    "compact", "full",
    "mobile", "desktop",
    "responsive",
    "print", "pdf",
    "csv", "tsv",
    "json", "xml",
    "yaml", "yml",
    "html", "text", "plain",
    "raw", "minified",
    "compressed", "zip", "gz",
    "encrypted", "signed",
    "checksum", "md5", "sha1", "sha256",
    "signature", "hmac",
    "digest", "hash",
    "iv", "nonce", "salt",
    "cipher", "algorithm",
    "public", "private",
    "cert", "certificate",
    "crl", "ocsp",
    "saml", "saml_request", "saml_response",
    "relay_state", "sso",
    "sp", "idp",
    "metadata", "meta",
    "discovery", "openid",
    "webfinger", "jwks",
    "jku", "jwk",
    "kty", "use", "alg",
    "n", "e", "d", "p", "q",
    "dp", "dq", "qi",
    "x5c", "x5t", "x5u",
    "kid", "thumbprint",
    "iat", "exp", "nbf",
    "iss", "sub", "aud",
    "jti", "typ", "cty",
    "azp", "at_hash", "c_hash",
    "s_hash", "nonce",
    "auth_time", "acr", "amr",
    "realm", "realm_id",
    "tenant", "tenant_id",
    "organization", "org_id",
    "workspace", "workspace_id",
    "project", "project_id",
    "board", "board_id",
    "sprint", "sprint_id",
    "task", "task_id",
    "issue", "issue_id",
    "ticket", "ticket_id",
    "incident", "incident_id",
    "case", "case_id",
    "job", "job_id",
    "run", "run_id",
    "build", "build_id",
    "deploy", "deploy_id",
    "release", "release_id",
    "tag", "tag_name",
    "branch", "branch_name",
    "commit", "commit_id",
    "pr", "pr_number",
    "merge", "merge_id",
    "diff", "patch",
    "change", "changeset",
    "review", "review_id",
    "approval", "approver",
    "assignee", "assignee_id",
    "reporter", "reporter_id",
    "watcher", "watcher_id",
    "votes", "vote_count",
    "comment_count",
    "attachment_count",
    "subtask", "subtasks",
    "parent", "parent_id",
    "child", "children",
    "related", "relates_to",
    "blocked_by", "blocks",
    "depends_on", "dependency",
    "epic", "epic_id",
    "milestone", "milestone_id",
    "sprint", "sprint_id",
    "story", "story_id",
    "point", "points",
    "estimate", "estimation",
    "time_spent", "time_remaining",
    "started_at", "completed_at",
    "due_date", "deadline",
    "progress", "percentage",
    "status", "state",
    "category", "categories",
    "label", "labels",
    "component", "components",
    "fix_version", "affected_version",
    "environment", "browser",
    "severity", "priority",
    "resolution", "resolved_at",
    "closed_at", "reopened_at",
    "duplicate_of", "related_to",
    "has_attachment", "has_comment",
    "watchers", "subscribers",
    "participants", "collaborators",
    "followers", "contributors",
]

# ──────────────────────────────────────────────────────────────────────────────
#  SKIP STATUS CODES
# ──────────────────────────────────────────────────────────────────────────────

SKIP_STATUS_CODES = {
    301, 302, 303, 307, 308,  # Redirects
    403,                       # Forbidden
    404,                       # Not Found
    405,                       # Method Not Allowed
    500, 502, 503, 504,       # Server errors
}

# Keep these codes
KEEP_STATUS_CODES = {200, 201, 202, 204, 206, 304, 400, 401, 406, 410, 412, 415, 422, 429}

# ──────────────────────────────────────────────────────────────────────────────
#  HTTP REQUEST ENGINE
# ──────────────────────────────────────────────────────────────────────────────

def build_http_request(method: str, host: str, path: str, headers: dict, body: str = "") -> bytes:
    """Build raw HTTP/1.1 request bytes."""
    request_line = f"{method} {path} HTTP/1.1\r\n"
    header_lines = f"Host: {host}\r\n"
    header_lines += f"User-Agent: Tech-Intelligence/1.0 (Security Assessment Tool)\r\n"
    header_lines += "Accept: */*\r\n"
    header_lines += "Connection: close\r\n"
    for k, v in headers.items():
        header_lines += f"{k}: {v}\r\n"
    if body:
        header_lines += f"Content-Length: {len(body)}\r\n"
    header_lines += "\r\n"
    return (request_line + header_lines).encode() + (body.encode() if body else b"")


def parse_http_response(raw: bytes) -> Tuple[int, dict, str]:
    """Parse raw HTTP response into (status_code, headers_dict, body)."""
    headers = {}
    try:
        header_part, _, body_bytes = raw.partition(b"\r\n\r\n")
        header_text = header_part.decode("utf-8", errors="replace")
        lines = header_text.split("\r\n")
        status_line = lines[0] if lines else ""
        # Extract status code
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) >= 2 else 0
        # Parse headers
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = body_bytes.decode("utf-8", errors="replace")
        return status_code, headers, body
    except Exception:
        return 0, {}, ""


def send_request(target_url: str, param_name: str, position: str,
                 method: str = "GET", body_template: str = "") -> Tuple[int, str, str]:
    """
    Send HTTP request with the param at the specified position.
    Returns (status_code, status_line, param_name).
    """
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.netloc
    scheme = parsed.scheme or "http"
    base_path = parsed.path or "/"
    query = parsed.query

    param_value = "test"
    path = base_path

    if position == "begin":
        # param at beginning of query string
        if query:
            path = f"{base_path}?{param_name}={param_value}&{query}"
        else:
            path = f"{base_path}?{param_name}={param_value}"
    elif position == "end":
        if query:
            path = f"{base_path}?{query}&{param_name}={param_value}"
        else:
            path = f"{base_path}?{param_name}={param_value}"
    elif position == "begin_path":
        # param in path before extension
        dot_pos = base_path.rfind(".")
        slash_pos = base_path.rfind("/")
        if dot_pos > slash_pos:
            path = f"{base_path[:dot_pos]}/{param_name}{base_path[dot_pos:]}"
        else:
            path = f"{base_path}/{param_name}"
    elif position == "end_path":
        path = f"{base_path}/{param_name}"
    elif position == "both":
        # Both query string and path
        path_with = f"{base_path}/{param_name}"
        if query:
            path_with = f"{path_with}?{query}&{param_name}={param_value}"
        else:
            path_with = f"{path_with}?{param_name}={param_value}"
        path = path_with

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    body = ""
    if method == "POST" and body_template:
        if "{param}" in body_template:
            body = body_template.replace("{param}", param_name)
        elif "{value}" in body_template:
            body = body_template.replace("{value}", param_value)
        else:
            body = f"{param_name}={param_value}"

    raw_request = build_http_request(method, host, path, headers, body)

    try:
        port = 443 if scheme == "https" else (parsed.port or 80)
        timeout = 10
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        sock.sendall(raw_request)

        response_data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break
        sock.close()

        status_code, resp_headers, resp_body = parse_http_response(response_data)
        status_line = ""
        if response_data:
            first_line = response_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            status_line = first_line

        return status_code, status_line, param_name

    except Exception as e:
        return 0, f"Error: {str(e)}", param_name


# ──────────────────────────────────────────────────────────────────────────────
#  REPORTING
# ──────────────────────────────────────────────────────────────────────────────

def generate_txt_report(results: List[tuple], target: str, position: str, method: str, timestamp: str) -> str:
    """Generate a clean TXT report."""
    lines = []
    lines.append("=" * 80)
    lines.append(f"  TECH-INTELLIGENCE - Parameter Discovery Report")
    lines.append("=" * 80)
    lines.append(f"  Target       : {target}")
    lines.append(f"  Position     : {position}")
    lines.append(f"  Method       : {method}")
    lines.append(f"  Timestamp    : {timestamp}")
    lines.append(f"  Parameters Found : {len(results)}")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"{'PARAMETER':<35} {'STATUS':<12} {'STATUS LINE':<40}")
    lines.append("-" * 80)
    for status_code, status_line, param_name in results:
        status_str = str(status_code) if status_code else "ERROR"
        lines.append(f"{param_name:<35} {status_str:<12} {status_line[:60]:<40}")
    lines.append("")
    lines.append("=" * 80)
    lines.append("  Report generated by Tech-Intelligence v1.0")
    lines.append("  Authorized Security Testing Only")
    lines.append("=" * 80)
    return "\n".join(lines)


def generate_html_report(results: List[tuple], target: str, position: str, method: str, timestamp: str) -> str:
    """Generate a professional HTML report."""
    rows = ""
    for status_code, status_line, param_name in results:
        status_code_str = str(status_code) if status_code else "ERROR"
        color = "#00aa00" if status_code == 200 else "#e67e22" if status_code in (301, 302) else "#e74c3c"
        rows += f"""
        <tr>
            <td><code>{param_name}</code></td>
            <td><span class="status-code" style="color:{color};font-weight:bold;">{status_code_str}</span></td>
            <td><code>{status_line[:80]}</code></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tech-Intelligence - Parameter Discovery Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border: 1px solid #30363d; border-radius: 12px; padding: 30px; margin-bottom: 30px; }}
    .header h1 {{ color: #58a6ff; font-size: 28px; margin-bottom: 5px; }}
    .header .subtitle {{ color: #8b949e; font-size: 14px; }}
    .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 20px; }}
    .info-item {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 12px 16px; }}
    .info-item .label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
    .info-item .value {{ color: #c9d1d9; font-size: 16px; font-weight: 600; margin-top: 4px; }}
    .summary {{ background: #161b22; border: 1px solid #21262d; border-radius: 12px; padding: 20px; margin-bottom: 30px; display: flex; gap: 20px; }}
    .summary-item {{ flex: 1; text-align: center; padding: 15px; }}
    .summary-item .number {{ font-size: 36px; font-weight: 700; }}
    .summary-item .number.green {{ color: #3fb950; }}
    .summary-item .number.yellow {{ color: #d29922; }}
    .summary-item .number.red {{ color: #f85149; }}
    .summary-item .desc {{ color: #8b949e; font-size: 13px; margin-top: 5px; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; }}
    th {{ background: #21262d; color: #58a6ff; padding: 14px 16px; text-align: left; font-weight: 600; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }}
    td {{ padding: 10px 16px; border-top: 1px solid #21262d; font-size: 14px; }}
    tr:hover {{ background: #1c2128; }}
    code {{ background: #0d1117; padding: 2px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 13px; }}
    .footer {{ text-align: center; margin-top: 40px; color: #484f58; font-size: 12px; }}
    .badge {{ display: inline-block; background: #1f6feb; color: white; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
    @media (max-width: 768px) {{ .info-grid {{ grid-template-columns: 1fr; }} .summary {{ flex-direction: column; }} }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 Tech-Intelligence</h1>
        <div class="subtitle">HTTP Parameter Discovery &mdash; Vulnerability Assessment Report</div>
        <div class="info-grid">
            <div class="info-item"><div class="label">Target</div><div class="value">{target}</div></div>
            <div class="info-item"><div class="label">Timestamp</div><div class="value">{timestamp}</div></div>
            <div class="info-item"><div class="label">Parameter Position</div><div class="value">{position}</div></div>
            <div class="info-item"><div class="label">Method</div><div class="value">{method}</div></div>
        </div>
    </div>

    <div class="summary">
        <div class="summary-item">
            <div class="number green">{len(results)}</div>
            <div class="desc">Parameters Discovered</div>
        </div>
        <div class="summary-item">
            <div class="number yellow">{sum(1 for s,_,_ in results if s in (200, 201, 202, 204))}</div>
            <div class="desc">Successful (2xx)</div>
        </div>
        <div class="summary-item">
            <div class="number red">{sum(1 for s,_,_ in results if s in (400, 401, 403, 404, 500))}</div>
            <div class="desc">Errors / Rejected</div>
        </div>
    </div>

    <table>
        <thead><tr><th>Parameter</th><th>Status</th><th>Response Line</th></tr></thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <div class="footer">
        Generated by <strong>Tech-Intelligence v1.0</strong> &mdash; Authorized Security Testing Only
    </div>
</div>
</body>
</html>"""
    return html


def generate_json_report(results: List[tuple], target: str, position: str, method: str, timestamp: str) -> str:
    """Generate JSON report."""
    data = {
        "tool": "Tech-Intelligence v1.0",
        "target": target,
        "timestamp": timestamp,
        "position": position,
        "method": method,
        "parameters_found": len(results),
        "results": [
            {
                "parameter": param_name,
                "status_code": status_code,
                "status_line": status_line
            }
            for status_code, status_line, param_name in results
        ]
    }
    return json.dumps(data, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
#  MAIN INTERACTIVE FLOW
# ──────────────────────────────────────────────────────────────────────────────

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(Colors.colorize(BANNER, Colors.CYAN))
    print()
    print(Colors.colorize("  [!] AUTHORIZED USE ONLY — I have permission to perform this pentest", Colors.RED + Colors.BOLD))
    print(Colors.colorize("  [!] This tool is for authorized security testing purposes only.", Colors.YELLOW))
    print()
    time.sleep(1.5)

    # ─── STEP 1: TARGET ───────────────────────────────────────────────────────
    print(Colors.colorize("  ════════════════════════════════════════════════════════════════", Colors.CYAN))
    print(Colors.colorize("  [STEP 1/6] TARGET URL", Colors.BOLD + Colors.BLUE))
    print(Colors.colorize("  ════════════════════════════════════════════════════════════════", Colors.CYAN))
    print()
    print(Colors.colorize("  Enter the target URL (e.g., https://target.com/page.php)", Colors.GREEN))
    print(Colors.colorize("  Or a specific endpoint (e.g., https://target.com/api/users)", Colors.GREEN))
    print()

    target_url = ""
    while not target_url:
        target_input = input(Colors.colorize("  target > ", Colors.CYAN + Colors.BOLD)).strip()
        if target_input:
            if not target_input.startswith("http"):
                target_url = "http://" + target_input
            else:
                target_url = target_input
        else:
            print(Colors.colorize("  [!] Target URL cannot be empty.", Colors.RED))

    print()
    print(Colors.colorize(f"  [+] Target set to: {target_url}", Colors.GREEN))

    # ─── STEP 2: METHOD ───────────────────────────────────────────────────────
    print()
    print(Colors.colorize("  ════════════════════════════════════════════════════════════════", Colors.CYAN))
    print(Colors.colorize("  [STEP 2/6] HTTP METHOD", Colors.BOLD + Colors.BLUE))
    print(Colors.colorize("  ════════════════════════════════════════════════════════════════", Colors.CYAN))
    print()
    print(Colors.colorize("  Choose HTTP method:", Colors.GREEN))
    print(Colors.colorize("    [1] GET  (default — query string parameters)", Colors.YELLOW))
    print(Colors.colorize("    [2] POST (body parameters)", Colors.YELLOW))
    print()
    method_choice = input(Colors.colorize("  method > ", Colors.CYAN + Colors.BOLD)).strip() or "1"
    method = "POST" if method_choice == "2" else "GET"
    print(Colors.colorize(f"  [+] Method: {method}", Colors.GREEN))

    body_template = ""
    if method == "POST":
        print()
        print(Colors.colorize("  Enter POST body template. Use {param} as placeholder:", Colors.GREEN))
        print(Colors.colorize("  Example: username={param}&password=test", Colors.YELLOW))
        body_template = input(Colors.colorize("  body > ", Colors.CYAN + Colors.BOLD)).strip()
        if not body_template:
            body_template = "{param}=test"
            print(Colors.colorize(f"  [+] Using default body: {body_template}", Colors.YELLOW))

    # ─── STEP 3: WORDLIST ─────────────────────────────────────────────────────
    print()
    print(Colors.colorize("  ════════════════════════════════════════════════════════════════", Colors.CYAN))
    print(Colors.colorize("  [STEP 3/6] WORDLIST SELECTION", Colors.BOLD + Colors.BLUE))
    print(Colors.colorize("  ════════════════════════════════════════════════════════════════", Colors.CYAN))
    print()
    print(Colors.colorize("  Choose wordlist option:", Colors.GREEN))
    print(Colors.colorize("    [1] Use built-in powerful wordlist (2,500+ parameters)", Colors.YELLOW))
    print(Colors.colorize("    [2] Use custom wordlist file", Colors.YELLOW))
    print(Colors.colorize("    [3] Use built-in + custom (combined)", Colors.YELLOW))
    print()

    wordlist_choice = input(Colors.colorize("  wordlist > ", Colors.CYAN + Colors.BOLD)).strip() or "1"
    params = []

    if wordlist_choice == "1":
        params = DEFAULT_PARAM_WORDLIST
        print(Colors.colorize(f"  [+] Loaded {len(params)} built-in parameters.", Colors.GREEN))

    elif wordlist_choice == "2":
        wl_path = ""
        while not wl_path:
            wl_path = input(Colors.colorize("  wordlist path > ", Colors.CYAN + Colors.BOLD)).strip()
            if os.path.isfile(wl_path):
                with open(wl_path, "r", encoding="utf-8", errors="replace") as f:
                    params = [line.strip() for line in f if line.strip()]
                print(Colors.colorize(f"  [+] Loaded {len(params)} custom parameters from {wl_path}", Colors.GREEN))
            else:
                print(Colors.colorize(f"  [!] File not found: {wl_path}", Colors.RED))
                wl_path = ""

    elif wordlist_choice == "3":
        params = list(DEFAULT_PARAM_WORDLIST)
        wl_path = ""
        while not wl_path:
            wl_path = input(Colors.colorize("  custom wordlist path > ", Colors.CYAN + Colors.BOLD)).strip()
            if os.path.isfile(wl_path):
                with open(wl_path, "r", encoding="utf-8", errors="replace") as f:
                    custom_params = [line.strip() for line in f if line.strip()]
                params.extend(custom_params)
                # Deduplicate preserving order
                seen = set()
                params_dedup = []
                for p in params:
                    if p not in seen:
                        seen.add(p)
                        params_dedup.append(p)
                params = params_dedup
                print(Colors.colorize(f"  [+] Loaded {len(params)} parameters (built-in + {len(custom_params)} custom).", Colors.GREEN))
            else