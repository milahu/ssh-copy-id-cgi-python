#! /usr/bin/env python3

# html version of ssh-copy-id

# add a ssh public key to a ssh server

# ssh-copy-id -- use locally available keys to authorise logins on a remote machine

# https://wiki.archlinux.org/title/SSH_keys
# the public key needs to be concatenated with ~/.ssh/authorized_keys
# cat ~/id_ecdsa.pub >> ~/.ssh/authorized_keys

# https://serverfault.com/questions/518821/how-can-you-do-dynamic-key-based-ssh-similar-to-github

# https://serverfault.com/questions/162238/openssh-with-public-keys-from-database

# here we use the $HOME/.ssh/authorized_keys file
# because we have a small number (1 to 1000) of users
# for large-scale solutions see
# https://github.com/go-gitea/gitea
# https://git.sr.ht/~sircmpwn/meta.sr.ht
# https://github.com/gitlabhq/gitlabhq

import sys
import os
#import io
#import json
#import glob
#import pathlib
#import types
import time
#import re

# requirements
#import captcha # https://pypi.org/project/captcha/
from captcha.image import ImageCaptcha



# global config
captcha_hash_secret = b"asdfguessmehasdufawewohahahhaha" # TODO change
# user has 1 minute to solve captcha
captcha_seconds = 60
#captcha_seconds = 600 # 10 min
authorized_keys_path = "/home/rsync/.ssh/authorized_keys" # TODO change
authorized_keys_size_max = 100 * 200 # about 100 users. min entry size is 100 bytes
#num_users_max = 1000 # no, this requires parsing the file
comment_size_max = 100
pubkey_algo_required = "ed25519"
pubkey_key_size_required = 68
pubkey_key_regex_required = "[0-9a-zA-Z/+]{68}"
pubkey_key_example_key = "A" * 68
pubkey_key_example = f"ssh-ed25519 {pubkey_key_example_key} some comment"
username_regex_required = "[a-zA-Z][0-9a-zA-Z_.-]{3,20}"
username_example = "example_username"

"""
while true; do
  yes | ssh-keygen -t ed25519 -C "some comment" -P "" -f ~/.ssh/id_some_name >/dev/null;
  cat /home/user/.ssh/id_some_name.pub;
  sleep 1;
done
"""



# global state
is_cgi = False

captcha_time_slot = str(round(time.time() / captcha_seconds + 0.5)).encode("ascii")
captcha_hash_seed = captcha_hash_secret + captcha_time_slot



def html_entities_encode(s, quote=True):
    """
    based on html.escape in python3-3.11.7/lib/python3.11/html/__init__.py

    Replace special characters "&", "<" and ">" to HTML-safe sequences.
    If the optional flag quote is true (the default), the quotation mark
    characters, both double quote (") and single quote (') characters are also
    translated.
    """
    s = s.replace("&", "&amp;") # Must be done first!
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    if quote:
        s = s.replace('"', "&quot;")
        s = s.replace('\'', "&#x27;")
    return s



def show_start_cgi(inputs=None, error=None):

    import base64

    def write(line=b""):
        sys.stdout.buffer.write(line + b"\n")

    # if we dont flush sys.stdout here, then sys.stdout.buffer is written first
    #sys.stdout.flush()
    #sys.stdout.buffer.write(b'<img src="data:image/png,base64">')
    #sys.stdout.buffer.flush()

    write(b"Status: 200")
    write(b"Content-Type: text/html")
    write()

    if not inputs:
        inputs = dict()

    # set default values
    for key in ["username", "pubkey", "comment"]:
        if key in inputs:
            continue
        if key == "pubkey":
            inputs[key] = pubkey_key_example
        elif key == "username":
            inputs[key] = username_example
        else:
            inputs[key] = key

    for key, val in inputs.items():
        val = html_entities_encode(val)
        val = val.encode("utf8", errors="replace")
        inputs[key] = val

    if error:
        error = html_entities_encode(error)
        error = error.encode("utf8", errors="replace")

    import random
    # 1 and 7 are very similar...
    captcha_text = "".join(random.choices("0123456789", k=8))

    import hashlib
    captcha_hash = hashlib.sha256(captcha_hash_seed + captcha_text.encode("ascii")).hexdigest().encode("ascii")

    captcha_png_bytes = ImageCaptcha(240, 60).generate(captcha_text).getvalue()

    write(b'<!doctype html>')
    write(b'<html>')
    write(b'<head>')
    write(b'<meta charset="utf-8">')
    write(b'<title>ssh pubkey add</title>')
    write(b'<style>')
    #write(b'* { font-family: monospace; font-size: 100%; font-weight: normal; }')
    write(b'input, textarea { border: solid 1px black; margin: 2px; padding: 0.5em; }')
    write(b'textarea { overflow: auto; overflow-y: scroll; outline: none; box-shadow: none; resize: none; scrollbar-width: auto; }')
    # invert colors in darkmode. this works only with chromium + darkreader, not with tor-browser + darkreader
    write(b'@media screen { :root[data-darkreader-mode="dynamic"] .darkmode-invert { filter: invert(); } }')
    write(b'</style>')
    write(b'</head>')
    write(b'<body style="margin: 0; padding: 0; ">')
    write(b'<form method="post" enctype="multipart/form-data" accept-charset="UTF-8" style="display: flex; flex-direction: column; height: 100vh; overflow: hidden; ">')
    #write(b'<h1>guestbook</h1>')
    write(b'<div>create <a href="https://wiki.archlinux.org/title/SSH_keys">ssh key</a> with</div>')
    write(b'<pre>ssh-keygen -t ed25519 -C "some comment" -P "" -f $HOME/.ssh/id_some_name</pre>')
    write(b'<div>then paste pubkey from</div>')
    write(b'<pre>$HOME/.ssh/id_some_name.pub</pre>')
    #write(b'<textarea style="width:100%;height:100%; flex-grow:1" name="comment">comment</textarea>')
    write(b'<input name="username" value="' + inputs["username"] + b'">')
    write(b'<textarea style="flex-grow:1" name="pubkey">' + inputs["pubkey"] + b'</textarea>')
    if error:
        write(b'<div class="error" style="text-align: center">error: ' + error + b'</div>')
    #write(b'<div>debug: captcha_hash_seed = ' + captcha_hash_seed + b'</div>')
    write(b'<div style="display:flex; justify-content: center; align-items: center;">')
    write(b'  <img class="darkmode-invert" style="margin: 0 1em" src="data:image/png;base64,' + base64.b64encode(captcha_png_bytes) + b'">')
    write(b'  <input style="margin: 0 1em" name="captcha" value="captcha">')
    write(b'  <input style="margin: 0 1em" type="submit" value="add">')
    write(b'</div>')
    write(b'<input type="hidden" name="captcha-hash" value="' + captcha_hash + b'">')
    write(b'</form>')
    write(b'</body>')
    write(b'</html>')

    sys.exit()



def error(msg):
    raise Exception(msg)



def error_cgi(msg, status=400):
    print(f"Status: {status}")
    print("Content-Type: text/plain")
    print()
    print("error: " + msg)
    sys.exit()



def main_cgi():

    if os.path.exists(authorized_keys_path) and os.path.getsize(authorized_keys_path) > authorized_keys_size_max:
        error("database is full")

    import urllib.parse

    #import os; _bytes = os.read(3, 100); error(repr(_bytes))

    # CONTENT_TYPE

    # debug
    #import json; error(json.dumps(dict(os.environ), indent=2))

    if os.environ.get("REQUEST_METHOD") == "GET":
        show_start_cgi()
        return
        """
        query_string = os.environ.get("QUERY_STRING")
        #query_list = urllib.parse.parse_qsl(query_string, keep_blank_values=True)
        query_dict = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        def get_arg(key):
            return query_dict.get(key, [None])[0]
        """

    if os.environ.get("REQUEST_METHOD") != "POST":
        error("only GET and POST requests are supported")

    # method == post

    #query_string = sys.stdin.read()
    #query_bytes = sys.stdin.buffer.read()
    # https://github.com/defnull/multipart
    import multipart
    wsgi_env = dict(os.environ)
    wsgi_env["wsgi.input"] = sys.stdin.buffer
    try:
        # IndexError @ len_first_line = len(lines[0])
        # https://github.com/defnull/multipart/issues/47
        #inputs, files = multipart.parse_form_data(os.environ)
        inputs, files = multipart.parse_form_data(wsgi_env)
    except Exception as exc:
        import traceback
        error(str(exc) + "\n\n" + traceback.format_exc())

    def get_arg(key):
        return inputs.get(key, "").strip()

    username = get_arg("username")
    pubkey = get_arg("pubkey")

    captcha = get_arg("captcha")
    captcha_hash = get_arg("captcha-hash")

    parts = pubkey.split(None, 2)
    pubkey_algo = parts[0]
    pubkey_key = parts[1]
    pubkey_comment = parts[2] if len(parts) > 2 else ""

    if pubkey_comment == "some comment":
        pubkey_comment = ""

    if comment_size_max and len(pubkey_comment) > comment_size_max:
        show_start_cgi(inputs, f"comment is too long. got {len(pubkey_comment)} chars. max {comment_size_max} chars")

    if username == username_example:
        show_start_cgi(inputs, f"enter YOUR username, not the example username")

    if pubkey == pubkey_key_example:
        show_start_cgi(inputs, f"enter YOUR pubkey, not the example pubkey")

    if pubkey_key == pubkey_key_example_key:
        show_start_cgi(inputs, f"enter YOUR pubkey, not the example pubkey")

    if not pubkey_algo.startswith("ssh-"):
        show_start_cgi(inputs, "pubkey_algo must start with 'ssh-'")

    pubkey_algo = pubkey_algo[4:]

    if pubkey_algo_required and pubkey_algo != pubkey_algo_required:
        show_start_cgi(inputs, f"algorithm {pubkey_algo_required} is required. got {repr(pubkey_algo)}. please use 'ssh-keygen -t {pubkey_algo_required}' to create your key")

    if pubkey_key_size_required and len(pubkey_key) != pubkey_key_size_required:
        show_start_cgi(inputs, f"key size {pubkey_key_size_required} is required. got {len(pubkey_key)}. this looks like an invalid key")

    import re
    if pubkey_key_regex_required and not re.fullmatch(pubkey_key_regex_required, pubkey_key):
        show_start_cgi(inputs, f"key regex {pubkey_key_regex_required} is required. this looks like an invalid key")

    if username_regex_required and not re.fullmatch(username_regex_required, username):
        show_start_cgi(inputs, f"username regex {username_regex_required} is required")

    import hashlib
    captcha_hash_actual = hashlib.sha256(captcha_hash_seed + captcha.encode("ascii", errors="replace")).hexdigest()

    if captcha_hash != captcha_hash_actual:
        show_start_cgi(inputs, "bad captcha. please retry")

    # good captcha

    # check if pubkey exists in database
    key_exists = False
    if os.path.exists(authorized_keys_path):
        with open(authorized_keys_path) as f:
            for line in f.readlines():
                line = line.strip()
                parts = line.split(None, 2)
                algo = parts[0][4:]
                key = parts[1]
                if algo == pubkey_algo and key == pubkey_key:
                    key_exists = True
                    break

    if not key_exists:
        # write to database
        # add datetime to avoid username collisions
        datetime = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        import json
        os.makedirs(os.path.dirname(authorized_keys_path), exist_ok=True)
        with open(authorized_keys_path, "a") as f:
            space_comment = ""
            if pubkey_comment:
                space_comment += " " + json.dumps(pubkey_comment)
            f.write(f"ssh-{pubkey_algo} {pubkey_key} {datetime} {username}{space_comment}\n")

    status = 200
    print(f"Status: {status}")
    print("Content-Type: text/plain")
    print()
    print("ok. your pubkey was added")
    sys.exit()



def main():

    global data_dir
    global is_cgi
    global error
    global unpack_zipfiles

    # see also https://github.com/technetium/cgli/blob/main/cgli/cgli.py

    if os.environ.get("GATEWAY_INTERFACE") == "CGI/1.1":
        is_cgi = True
        error = error_cgi

    if is_cgi:
        return main_cgi()

    raise NotImplementedError("no cli. cgi only")
    #return main_cli()



if __name__ == "__main__":
    main()
    sys.exit()
