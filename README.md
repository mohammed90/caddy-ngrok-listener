ngrok/Caddy Listener Wrapper
=============================

On March 9, 2023, ngrok announced the release of [ngrok-go](https://blog.ngrok.com/posts/ngrok-go)[^1], a Go package for embedding ngrok into a Go application. The package returns a `net.Listener`. This means it fits right into Caddy's [`listener_wrapper`](https://caddyserver.com/docs/json/apps/http/servers/listener_wrappers/)[^2]. Using this module, when Caddy asks for a listener, it will ask ngrok for the listener, for which ngrok return an ngrok ingress address that is publicly accessible. The public address is printed in logs and avaible on ngrok dashboard.

Currently, the module does not support the extended ngrok options, e.g. allow/deny CIDR. PRs are welcome.

[^1]: [Alan Shreve's tweet](https://twitter.com/inconshreveable/status/1633837669053792260)

[^2]: [`listener_wrappers` Caddyfile docs](https://caddyserver.com/docs/caddyfile/options#listener-wrappers)

## Example

### Caddyfile

```
{
	servers :80 {
		listener_wrappers {
			ngrok {
				auth_token $NGROK_AUTH_TOKEN
				tunnel http {
				}
			}
		}
	}
}
:80 {
	root * /path/to/site/root
	file_server
}
```
