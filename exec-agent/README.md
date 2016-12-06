Summary
---
Golang based server for executing commands and streaming process output logs,
also websocket-terminal.



Docs
---
- jsonrpc2.0 based [Webscoket API](docs/ws_api.md)
- jsonrpc2.0 based [Events](docs/events.md)
- [REST API](docs/rest_api.md)

Development
---

##### Link the sources to standard go workspace

```bash
export CHE_PATH=~/code/che
mkdir $GOPATH/src/github.com/eclipse/che -p
ln -s $CHE_PATH/exec-agent/src $GOPATH/src/github.com/eclipse/che/exec-agent
```

##### Install godep
```bash
go get github.com/tools/godep
```

##### Get all dependencies

```bash
cd $GOPATH/src/github.com/eclipse/che/exec-agent
$GOPATH/bin/godep restore
```

That's it, `$GOPATH/src/github.com/eclipse/che/exec-agent` project is ready.
