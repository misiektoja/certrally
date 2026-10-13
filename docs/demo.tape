# Records docs/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Run it with `make demo`, which builds certrally, puts it first on PATH and sets DEMO_DIR.
# The test CA listens on 127.0.0.1:8080, so that port must be free.

Output docs/demo.gif

Require certrally

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 960
Set Height 520
Set Padding 24
Set TypingSpeed 35ms

Hide
Type `export PS1='$ ' PS2='  ' CERTRALLY_SECRET=demo-secret && cd "$DEMO_DIR"` Enter
Type `certrally mock --ca-out ca.pem --force > mock.log 2>&1 &` Enter
Type `until grep -q 'Press Ctrl-C' mock.log; do sleep 0.1; done; clear` Enter
Sleep 1s
Show

Type "certrally enroll --server http://127.0.0.1:8080/.well-known/cmp \" Enter
Type "--ref demo --ca-cert ca.pem --subject CN=device-42 --key-type ml-dsa-65 \" Enter
Type "--cert-out device.pem --key-out device.key --force"
Sleep 500ms
Enter
Sleep 5s

Hide
Type "clear" Enter
Show

Type "certrally revoke --server http://127.0.0.1:8080/.well-known/cmp \" Enter
Type "--ca-cert ca.pem --cert device.pem --key device.key --yes"
Sleep 500ms
Enter
Sleep 4s

Hide
Type "kill %1" Enter
