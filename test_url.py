import urllib.parse

original = "https://www.kpcmedicalcollege.in/page.php?page-id=243%27%20AND%20%28SELECT"
unquoted = urllib.parse.unquote(original)
print("Unquoted:", unquoted)

# Re-quote
# We want to leave the scheme, host, path intact, and only quote what needs quoting.
safe_chars = ":/?&="
requoted = urllib.parse.quote(unquoted, safe=safe_chars)
print("Requoted:", requoted)

